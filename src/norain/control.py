"""内控制模块：协调各个模块的运行，控制它们的运行参数。

`norain run` 启动的就是它（Controller）。职责：
  - 审批：所有多模块交互操作、启动和结束模块都要经过 approve()。
  - 启动测试检测模式：按「分流 → 代理 → 监控」的顺序拉起，监控通过后激活互拉保活、启动自维持；
    这期间抑制自维持模块的拉起请求。
  - 代理模块的协议选择：protocol = "auto" 时按测速和连通性自适应切换（Selector）。
  - 分流模块的自更新：定期更新规则集；分流模块学到新名单后重新生成配置并重载。
  - 接受命令行（外控制模块）的请求，并把各模块的运行情况写到 status.json。

进程模型：本进程里代理（sing-box 监督器）、分流、监控、自维持各是一个线程；
另有一个独立的看门狗进程与本进程互拉（maintain.py）。

命令行与本进程之间用状态目录里的请求文件通信（`run/ctl/<id>.req.json` → `<id>.resp.json`）：
不占端口，不需要鉴权，权限由目录权限（0700）保证。
"""

from __future__ import annotations

import collections
import os
import signal
import statistics
import threading
import time

from norain_core import osutil
from norain_core.daemonctl import alive as pid_alive
from norain_core.errors import (BIZ_PROCESS_EXITED, BIZ_RESTART_LIMIT, EXIT_CONFLICT, EXIT_OK,
                                EXIT_PERMISSION, EXIT_RESTART_LIMIT, EXIT_TIMEOUT, NorainError)
from norain_core.log import Logger, RotatingFile, new_op_id
from norain_core.state import RUNNING, get_desired, read_json, write_json
from norain_core.supervisor import Spec, check_ports_free, record_error

from . import block, boot, generate, maintain, probe, rules
from .model import PROTOCOLS, ClientConfig
from .monitor import MEANING, OK, Monitor, Ports, report_text
from .paths import Paths
from .proxy import ProxyModule
from .routing import Classifier, Learned, Router, save_learned

BOOT, RUNNING_PHASE, REPAIRING, BLOCKED, STOPPING = "boot-test", "running", "repairing", "blocked", "stopping"
MODULES = ("proxy", "routing", "monitor", "maintain", "block", "repair", "boot", "control", "cli")
ACTIVE_MODULES = ("routing", "proxy", "monitor", "maintain")   # 有自己线程、可以启动和结束的模块
RELOAD_DEBOUNCE = 30.0   # 分流学习触发的重载之间的最小间隔（重载会中断已有连接）
STATE_HEARTBEAT = 30.0   # 状态没有变化时，状态文件最多隔这么久刷新一次
RULES_CHECK_INTERVAL = 60.0   # 多久看一次规则集是否到了更新时间（更新间隔以小时计，不需要每半秒看）
REQUEST_MAX_AGE = 120.0  # 命令行请求和回应文件的最长保留时间


# ---- 命令行 → 内控制 的请求通道 ------------------------------------------------

def send(paths: Paths, request: dict, *, timeout: float = 60.0) -> dict:
    """命令行一侧：发一个请求并等待回应。内控制进程没有运行时抛出错误。"""
    info = read_json(paths.runner) or {}
    if not pid_alive(info.get("pid")):
        raise NorainError("代理没有运行", exit_code=EXIT_CONFLICT, module="control", hint="先运行 norain start")
    rid = new_op_id()
    paths.ctl_dir.mkdir(parents=True, exist_ok=True)
    req, resp = paths.ctl_dir / f"{rid}.req.json", paths.ctl_dir / f"{rid}.resp.json"
    write_json(req, {**request, "id": rid, "at": time.time()})
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            data = read_json(resp)
            if data is not None:
                return data
            if not pid_alive(info.get("pid")):
                raise NorainError("代理进程在处理请求时退出了", exit_code=EXIT_CONFLICT, module="control")
            time.sleep(0.1)
        raise NorainError("内控制模块没有在限定时间内回应", exit_code=EXIT_TIMEOUT, module="control",
                          retryable=True)
    finally:
        req.unlink(missing_ok=True)
        resp.unlink(missing_ok=True)


# ---- 自适应选协议 --------------------------------------------------------------

class Selector:
    """按连通性和延迟在 Hysteria2 与 Trojan 之间选择（docs/decisions/0009）。

    每个协议各有一个本地探测入口，测量不受当前选择的影响。切换条件：
      - 当前协议连续 failure_threshold 次失败，而另一个协议可用 → 立即切换（不受冷却限制）；
      - 冷却期过后，当前协议的延迟中位数比另一个差到 latency_ratio 倍且差值超过 latency_margin_ms；
      - 指标不相上下时回到 prefer 指定的协议。
    """

    def __init__(self, cfg: ClientConfig, paths: Paths, log: Logger) -> None:
        self.cfg, self.paths, self.log = cfg, paths, log
        self.sel = cfg.proxy.selection
        self.ports = generate.probe_ports(cfg)
        self.samples = {p: collections.deque(maxlen=5) for p in PROTOCOLS}
        self.fail_streak = {p: 0 for p in PROTOCOLS}
        self.switched_at = float((read_json(paths.selection) or {}).get("switched_ts") or 0)
        self.next_at = 0.0
        self.last: dict | None = None

    def measure(self) -> dict:
        out = {}
        for p in PROTOCOLS:
            r = probe.http(self.sel.test_url, proxy=(generate.LOOPBACK, self.ports[p]),
                           timeout=self.cfg.monitor.timeout_seconds, via=p)
            ms = r.elapsed_ms if r.ok else None
            self.samples[p].append(ms)
            self.fail_streak[p] = 0 if r.ok else self.fail_streak[p] + 1
            out[p] = round(ms, 1) if ms is not None else None
        return out

    def _median(self, p: str) -> float | None:
        good = [s for s in self.samples[p] if s is not None]
        return statistics.median(good) if len(good) >= 3 else None

    def decide(self, active: str) -> tuple[str | None, str]:
        other = next(p for p in PROTOCOLS if p != active)
        other_up = bool(self.samples[other]) and self.samples[other][-1] is not None
        if self.fail_streak[active] >= self.sel.failure_threshold and other_up:
            return other, f"{active} 连续 {self.fail_streak[active]} 次探测失败"
        if time.time() - self.switched_at < self.sel.cooldown_seconds:
            return None, "冷却中"
        ma, mo = self._median(active), self._median(other)
        if ma is None or mo is None:
            return None, "样本不足"
        if ma > mo * self.sel.latency_ratio and ma - mo > self.sel.latency_margin_ms:
            return other, f"{active} 延迟中位数 {ma:.0f} ms，{other} 为 {mo:.0f} ms"
        if active != self.sel.prefer and mo <= ma:
            return other, f"指标相当，回到优先协议 {other}"
        return None, "保持"

    def tick(self, active: str) -> tuple[str | None, str]:
        self.next_at = time.monotonic() + self.sel.interval_seconds
        sample = self.measure()
        new, why = self.decide(active)
        self.last = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "sample_ms": sample, "active": active,
                     "decision": new or "keep", "reason": why}
        return new, why

    def record(self, new: str, reason: str) -> None:
        self.switched_at = time.time()
        data = read_json(self.paths.selection) or {}
        data.update({"active": new, "reason": reason, "switched_ts": self.switched_at,
                     "switched_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
        write_json(self.paths.selection, data)

    def status(self) -> dict:
        return {"last_result": self.last, "fail_streak": dict(self.fail_streak),
                "median_ms": {p: self._median(p) for p in PROTOCOLS}}


# ---- 内控制 --------------------------------------------------------------------

class Controller:
    def __init__(self, paths: Paths, *, autostart: bool = False) -> None:
        self.paths0 = paths
        self.paths = paths
        self.autostart = autostart
        self.phase = BOOT
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.user_stopped: set[str] = set()
        self.keepalive = False
        self.decisions: collections.deque[dict] = collections.deque(maxlen=20)
        self.last_request: dict | None = None
        self.modules: dict = {}
        self.selector: Selector | None = None
        self._op = threading.RLock()            # 串行化模块的启动 / 结束 / 重启
        self._stop = threading.Event()
        self._exit_code = EXIT_OK
        self._reload_wanted: float | None = None
        self._last_reload = 0.0
        self._rules_thread: threading.Thread | None = None
        self._rules_report: dict | None = None
        self._boot_info: dict = {}
        self._autostart_registered: bool | None = None
        self._last_runner: dict | None = None
        self._last_status: dict | None = None
        self._state_written_at = 0.0
        self._next_rules_check = 0.0
        self.log: Logger = Logger("control", stderr=True)

    # ---- 构建 ----

    def _logger(self, module: str) -> Logger:
        return Logger(module, op_id=self.log.op_id, sink=self.log.sink, stderr=False,
                      level=self.cfg.logging.level)

    def _prepare(self) -> None:
        from . import runner
        self.prep = runner.prepare(self.paths0, apply=True)
        self.cfg: ClientConfig = self.prep.cfg
        self.paths = self.prep.paths
        sink = RotatingFile(self.paths.log_file, max_bytes=self.cfg.logging.max_size_mb << 20,
                            keep=self.cfg.logging.retain_files)
        self.log = Logger("control", op_id=self.log.op_id, sink=sink, stderr=False, level=self.cfg.logging.level)

    def _spec(self) -> Spec:
        cfg, p = self.cfg, self.paths
        return Spec(
            binary=self.prep.binary.path, config_json=p.current_json,
            config_version=(read_json(p.meta_json) or {}).get("config_version", ""),
            listeners=generate.listeners(cfg), check_interval=cfg.supervisor.check_interval_seconds,
            restart_limit=cfg.supervisor.restart_limit, backoff=cfg.supervisor.backoff_seconds,
            log_file=p.log_file, log_max_bytes=cfg.logging.max_size_mb << 20,
            log_keep=cfg.logging.retain_files, log_level=cfg.logging.level,
            runner_file=p.proxy_state, last_error_file=p.last_error, stop_file=p.proxy_stop,
            on_line=self.router.feed,
            windows_console=(cfg.dns.fake_ip and cfg.proxy.traffic_mode == "tun"
                             and self.prep.binary.path.suffix.lower() == ".exe"),
            resolve_listeners=self._reload_listeners)

    def _reload_listeners(self) -> list:
        """重载后按磁盘上的最新配置重算监听端口（重载可能改了 dns.fake_ip 或 TUN 设置）。"""
        from .model import load_config
        return generate.listeners(load_config(self.paths.config))

    def _local_proxy(self) -> tuple[str, int]:
        listen = self.cfg.local.listen
        host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(listen, listen)
        return host, self.cfg.local.port

    def _probe(self, name: str) -> probe.Proxy:
        if not generate.needs_probes(self.cfg):
            return None
        port = generate.probe_ports(self.cfg).get(name)
        return (generate.LOOPBACK, port) if port else None

    def _monitor_ports(self) -> Ports:
        if not self.proxy.ready:
            return Ports()
        return Ports(routed=self._local_proxy(), direct=self._probe("direct"))

    @property
    def active(self) -> str:
        return generate.active_protocol(self.cfg, self.paths)

    def _build_modules(self) -> None:
        cfg, paths = self.cfg, self.paths
        self.geo = rules.Geo(self.prep.binary.path, paths)
        self.monitor = Monitor(cfg, self._monitor_ports, self.geo, self._logger("monitor"),
                               on_change=lambda code, rnd: self.maintainer.notify(code, rnd.reason))
        classifier = Classifier(cfg, paths, self.geo, direct=self._probe("direct"),
                                proxy=self._probe(self.active), internet_ok=self.monitor.internet_ok)
        self.router = Router(cfg, paths, classifier, self._logger("routing"), on_change=self._want_reload)
        self.proxy = ProxyModule(self._spec,
                                 sysproxy_state=(paths.sysproxy_state
                                                 if cfg.proxy.traffic_mode == "system-proxy" else None))
        self.maintainer = maintain.Maintainer(self, self._logger("maintain"))
        self.selector = Selector(cfg, paths, self._logger("control")) if cfg.proxy.protocol == "auto" else None
        self.modules = {"routing": self.router, "proxy": self.proxy, "monitor": self.monitor,
                        "maintain": self.maintainer}

    # ---- 审批 ----

    def approve(self, action: str, module: str, requester: str) -> tuple[bool, str]:
        """所有启动 / 结束 / 重启模块的请求都从这里过。返回 (是否批准, 原因)。"""
        ok, why = True, "批准"
        starting = action in ("start", "restart")
        if module not in ACTIVE_MODULES:
            ok, why = False, f"{module} 不是可以单独启停的模块"
        elif self.phase == STOPPING:
            ok, why = False, "正在停止"
        elif self.phase == BLOCKED and starting:
            ok, why = False, "已进入阻断模式"
        elif starting and requester != "boot" and get_desired(self.paths.desired) != RUNNING:
            ok, why = False, "用户已要求停止（期望状态为 stopped）"
        elif self.phase == BOOT and requester not in ("boot", "control"):
            ok, why = False, "正在启动测试，暂不受理"          # 抑制自维持模块的拉起
        elif self.phase == REPAIRING and requester not in ("maintain", "control"):
            ok, why = False, "自维持模块正在修复，稍后再试"      # 修复期间不让别人插手
        elif module == "monitor" and starting and not self.cfg.monitor.enabled:
            ok, why = False, "配置里关闭了监控（monitor.enabled = false）"
        self.decisions.append({"at": time.strftime("%H:%M:%S"), "action": action, "module": module,
                               "by": requester, "approved": ok, "reason": why})
        (self.log.debug if ok else self.log.info)("control.approval", action=action, target=module,
                                                  requester=requester, approved=ok, reason=why)
        return ok, why

    def start_module(self, name: str, requester: str) -> tuple[bool, str]:
        ok, why = self.approve("start", name, requester)
        if not ok:
            return False, why
        with self._op:
            try:
                self.modules[name].start()
            except Exception as e:  # noqa: BLE001
                return False, f"启动失败：{e}"
            if requester == "cli":
                self.user_stopped.discard(name)
            if name == "maintain" and self.cfg.maintain.watchdog and self.keepalive:
                self.activate_keepalive()
        return True, "已启动"

    def stop_module(self, name: str, requester: str) -> tuple[bool, str]:
        ok, why = self.approve("stop", name, requester)
        if not ok:
            return False, why
        with self._op:
            if requester == "cli":
                self.user_stopped.add(name)   # 用户手动停的模块，自维持不再拉起
            self.modules[name].stop()
            if name == "maintain" and requester == "cli":
                maintain.kill_watchdog(self.paths)
        return True, "已停止"

    def restart_proxy(self, requester: str, reason: str) -> tuple[bool, str]:
        """重新生成配置并重启 sing-box。生成或校验失败时保留旧配置继续运行。"""
        ok, why = self.approve("restart", "proxy", requester)
        if not ok:
            return False, why
        with self._op:
            try:
                res = generate.apply(self.cfg, self.prep.secret, self.paths, self.prep.binary.path)
            except NorainError as e:
                self.log.error("control.regenerate_failed", error=e.message, reason=reason)
                if self.proxy.alive():
                    return False, f"新配置没有通过校验，继续使用旧配置：{e.message}"
                res = None
            self.proxy.stop()
            self.router.classifier.proxy = self._probe(self.active)
            self.proxy.start()
            self._last_reload = time.monotonic()
            self.log.info("control.proxy_restarted", requester=requester, reason=reason,
                          config_version=res.version if res else None)
        return True, "已重启"

    # ---- 提供给自维持模块的接口 ----

    def monitor_code(self) -> int:
        return self.monitor.code if self.cfg.monitor.enabled else OK

    def verify(self, rounds: int) -> int:
        if not self.cfg.monitor.enabled:
            return OK if self.proxy.ready else maintain.PROXY_DOWN
        # 阻断修复期间蓝名单被额外放行：让监控跳过这些探测项，免得把「蓝名单还能通」
        # 当成「代理已经修好」
        exempt = block.exempt_hosts(self.cfg) if block.is_active(self.paths) else None
        return self.monitor.verify(rounds, exempt=exempt)

    def enter_repair(self, code: int) -> None:
        self.phase = REPAIRING
        self.monitor.pause()
        self.log.warn("control.phase", phase=REPAIRING, code=code)

    @property
    def stop_requested(self) -> bool:
        """本轮是否已被要求停止（_stop），或用户把期望状态改成了 stopped。

        循环里用它代替直接看期望状态：阻断先行之后，进入阻断那一刻期望状态还是 running，
        不能因为「已经不是 running」就说用户要停。
        """
        return self._stop.is_set() or get_desired(self.paths.desired) != RUNNING

    def leave_repair(self, outcome: str) -> None:
        if self.phase == REPAIRING:
            self.phase = RUNNING_PHASE
        self.monitor.resume(reset=True)
        self.log.info("control.phase", phase=self.phase, repair_outcome=outcome)

    def activate_keepalive(self) -> None:
        """激活互拉保活：拉起看门狗进程。"""
        self.keepalive = True
        if not maintain.watchdog_alive(self.paths):
            maintain.spawn_watchdog(self.paths)
            self.log.info("control.keepalive_activated")

    def set_override(self, *, dns_strategy: str | None) -> None:
        data = read_json(self.paths.selection) or {}
        if dns_strategy:
            data["dns_strategy"] = dns_strategy
        else:
            data.pop("dns_strategy", None)
        write_json(self.paths.selection, data)

    def clear_learned(self) -> None:
        self.router.learned = Learned()
        save_learned(self.paths, self.router.learned)

    def switch_protocol(self, requester: str, reason: str) -> str | None:
        """切换到另一个协议（只写选择结果，由调用方负责重启代理）。"""
        if self.selector is None:
            return None
        new = next(p for p in PROTOCOLS if p != self.active)
        self.selector.record(new, f"{requester}: {reason}")
        self.log.warn("control.protocol_switched", new=new, requester=requester, reason=reason)
        return new

    def request_shutdown(self, *, blocked: bool = False, code: int = 0) -> None:
        if blocked:
            self.phase = BLOCKED
        self._exit_code = EXIT_RESTART_LIMIT if (blocked or code) else EXIT_OK
        if code:
            record_error(self.paths.last_error, BIZ_RESTART_LIMIT if code == maintain.PROXY_DOWN else code,
                         f"代理无法恢复（错误码 {code}：{MEANING.get(code, '代理进程无法维持')}）"
                         + ("，已进入阻断模式" if blocked else "，阻断没有生效"))
        self._stop.set()

    # ---- 运行参数的调整 ----

    def _want_reload(self) -> None:
        self._reload_wanted = time.monotonic()

    def _tick_reload(self) -> None:
        if self._reload_wanted is None or self.phase != RUNNING_PHASE:
            return
        if time.monotonic() - self._last_reload < RELOAD_DEBOUNCE:
            return
        self._reload_wanted = None
        self.restart_proxy("control", "分流名单或规则集有更新")

    def _tick_selection(self) -> None:
        sel = self.selector
        if sel is None or self.phase != RUNNING_PHASE or time.monotonic() < sel.next_at or not self.proxy.ready:
            return
        new, why = sel.tick(self.active)
        if new:
            sel.record(new, why)
            self.log.warn("control.protocol_switched", new=new, requester="control", reason=why)
            self.restart_proxy("control", f"自适应切换协议：{why}")

    def _update_rules(self) -> None:
        try:
            px = self._local_proxy() if self.proxy.ready else None
            rep = rules.update(self.cfg, self.paths, proxy=px, binary=self.prep.binary.path)
            self._rules_report = {**rep, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
            self.log.info("control.rules_updated", **rep)
            if rep["updated"]:
                self._want_reload()
        except Exception as e:  # noqa: BLE001
            self.log.error("control.rules_update_failed", error=repr(e))

    def _tick_rules(self) -> None:
        """分流模块的自更新：到期时在后台线程里下载，不阻塞主循环。"""
        if self.phase != RUNNING_PHASE or time.monotonic() < self._next_rules_check:
            return
        if self._rules_thread and self._rules_thread.is_alive():
            return
        self._next_rules_check = time.monotonic() + RULES_CHECK_INTERVAL
        if rules.due(self.cfg, self.paths):
            self._rules_thread = threading.Thread(target=self._update_rules, name="norain-rules", daemon=True)
            self._rules_thread.start()

    # ---- 状态 ----

    def status(self) -> dict:
        mods = {name: self.modules[name].status() for name in ACTIVE_MODULES if name in self.modules}
        for name in self.user_stopped:
            if name in mods:
                mods[name]["stopped_by_user"] = True
        blk = block.status(self.paths)
        mods["block"] = {"state": "blocking" if blk["active"] else "idle", "last_result": blk if blk["active"] else None}
        mods["repair"] = {"state": "repairing" if self.phase == REPAIRING else "idle",
                          "last_result": self.maintainer.last_result}
        mods["boot"] = {"state": "testing" if self.phase == BOOT else "done", "mode": self.cfg.app.mode,
                        "autostart_registered": self._autostart_registered, "last_result": self._boot_info}
        mods["control"] = {"state": self.phase, "last_result": list(self.decisions)[-5:]}
        mods["cli"] = {"state": "listening", "last_result": self.last_request}
        return {
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "started_at": self.started_at,
            "pid": os.getpid(), "phase": self.phase, "traffic_mode": self.cfg.proxy.traffic_mode,
            "protocol": {"configured": self.cfg.proxy.protocol, "active": self.active,
                         "selection": self.selector.status() if self.selector else None},
            "monitor": {"code": self.monitor_code(), "meaning": MEANING.get(self.monitor_code(), "")},
            "rules": {"sets": rules.status(self.cfg, self.paths), "last_update": self._rules_report},
            "modules": mods,
        }

    def _write_state(self) -> None:
        """把运行状态写给命令行看。内容没有变化时不写盘（最多每 STATE_HEARTBEAT 秒刷新一次）；
        这两个文件丢了可以重建，所以不 fsync——否则常驻进程每秒都在强制刷盘。"""
        runner = {"pid": os.getpid(), "child_pid": self.proxy.child_pid, "ready": self.proxy.ready,
                  "restarts": self.proxy.restarts, "phase": self.phase, "started_at": self.started_at,
                  "log_file": str(self.paths.log_file)}
        status = self.status()
        stamp = status.pop("updated_at")
        now = time.monotonic()
        stale = now - self._state_written_at >= STATE_HEARTBEAT
        try:
            if stale or runner != self._last_runner or not self.paths.runner.exists():
                write_json(self.paths.runner, runner, durable=False)
                self._last_runner = runner
            if stale or status != self._last_status:
                write_json(self.paths.status_file, {**status, "updated_at": stamp}, durable=False)
                self._last_status = status
            if stale:
                self._state_written_at = now
        except OSError:
            pass

    # ---- 命令行请求 ----

    def _handle(self, req: dict) -> dict:
        op = req.get("op")
        if op == "module":
            name, action = req.get("name"), req.get("action")
            if name not in ACTIVE_MODULES:
                return {"ok": False, "message": f"{name} 不能单独启停；可以启停的模块：{'、'.join(ACTIVE_MODULES)}"}
            if action == "start":
                ok, why = self.start_module(name, "cli")
            elif action == "stop":
                ok, why = self.stop_module(name, "cli")
            elif name == "proxy":
                ok, why = self.restart_proxy("cli", "命令行请求")
            else:
                ok, why = self.stop_module(name, "cli")
                if ok:
                    ok, why = self.start_module(name, "cli")
            return {"ok": ok, "message": why, "module": self.modules[name].status()}
        if op == "reload":
            return self._reconfigure()
        if op == "monitor":
            rnd = self.monitor.check_once(feed=False)
            return {"ok": True, "result": rnd.as_dict(), "text": report_text(rnd)}
        if op == "select":
            if self.selector is None:
                return {"ok": False, "message": "protocol 不是 auto，没有自适应选择"}
            new, why = self.selector.tick(self.active)
            if new:
                self.selector.record(new, why)
                self.restart_proxy("cli", f"自适应切换协议：{why}")
            return {"ok": True, "active": self.active, "switched": bool(new), "reason": why,
                    "result": self.selector.status()}
        if op == "route":
            v = self.router.check(str(req.get("domain", "")))
            if v.changed:
                self._want_reload()
            return {"ok": True, "result": v.as_dict()}
        if op == "rules-update":
            self._update_rules()
            return {"ok": True, "result": self._rules_report}
        if op == "status":
            return {"ok": True, "result": self.status()}
        return {"ok": False, "message": f"未知请求：{op}"}

    def _serve(self) -> None:
        d = self.paths.ctl_dir
        try:
            names = sorted(os.listdir(d))   # 一次系统调用；目录不存在或为空是常态
        except OSError:
            return
        now = time.time()
        for name in names:
            if name.endswith(".resp.json"):
                # 命令行等不到回应就走了（超时、被中断）：没人会来取的回应不能一直堆在目录里
                try:
                    if now - (d / name).stat().st_mtime > REQUEST_MAX_AGE:
                        (d / name).unlink(missing_ok=True)
                except OSError:
                    pass
                continue
            if not name.endswith(".req.json"):
                continue
            req_file = d / name
            req = read_json(req_file)
            try:
                req_file.unlink(missing_ok=True)
            except OSError:
                continue   # 删不掉就不处理，否则同一个请求会被反复执行
            if not isinstance(req, dict):
                continue
            at = req.get("at", 0)
            if not isinstance(at, (int, float)) or now - at > REQUEST_MAX_AGE:
                continue
            # 回应文件名取自请求文件名，不信任请求内容里的 id（缺失时会 KeyError，拖垮整个内控制）
            rid = name[:-len(".req.json")]
            try:
                resp = self._handle(req)
            except NorainError as e:
                resp = {"ok": False, "message": e.message, "hint": e.hint}
            except Exception as e:  # noqa: BLE001 单个请求出错不能拖垮内控制
                resp = {"ok": False, "message": f"处理请求时出错：{e!r}"}
            self.last_request = {"at": time.strftime("%H:%M:%S"), "op": req.get("op"),
                                 "ok": resp.get("ok"), "message": resp.get("message")}
            try:
                write_json(d / f"{rid}.resp.json", resp, durable=False)
            except (OSError, TypeError, ValueError) as e:   # 回应写不出去只影响这一个请求
                self.log.error("control.response_failed", op=str(req.get("op")), error=repr(e))

    def _reconfigure(self) -> dict:
        """cfg.toml 改过之后重新加载：新配置通过校验才替换，否则继续用旧配置运行。"""
        from . import runner
        if self.phase != RUNNING_PHASE:
            return {"ok": False, "message": f"当前阶段是 {self.phase}，稍后再试"}
        try:
            new = runner.prepare(self.paths0, apply=False)
        except NorainError as e:
            detail = "；".join(f"{f.path} {f.message}" for f in e.field_errors) or e.message
            return {"ok": False, "message": f"新配置无效，继续使用旧配置：{detail}"}
        ready = False
        with self._op:
            self.phase = BOOT   # 重建期间抑制自维持
            try:
                # 先生成并运行 sing-box check。候选配置无效时保持旧模块完整运行，
                # 不要先停掉代理再把错误留给 finally 处理。
                generate.apply(new.cfg, new.secret, new.paths, new.binary.path)
                for name in ("maintain", "monitor", "routing", "proxy"):
                    self.modules[name].stop()
                self.prep, self.cfg, self.paths = new, new.cfg, new.paths
                self._build_modules()
                for name in ("routing", "proxy"):
                    self.modules[name].start()
                ready = self.proxy.wait_ready(30)
                if self.cfg.monitor.enabled and "monitor" not in self.user_stopped:
                    self.monitor.start()
            finally:
                self.phase = RUNNING_PHASE
                # 无论重建是否成功，自维持都要回到岗位上（除非用户手动停了它）
                if "maintain" not in self.user_stopped:
                    self.modules["maintain"].start()
        try:
            self._autostart_registered = boot.registered()
        except Exception:  # noqa: BLE001
            pass
        return {"ok": ready, "message": "已按新配置重新加载" if ready else "已重新加载，但代理还没有就绪"}

    # ---- 主流程 ----

    def _boot_sequence(self) -> None:
        """启动测试检测模式：分流 → 代理 → 监控；通过后激活互拉保活并启动自维持。"""
        cfg = self.cfg
        self.start_module("routing", "boot")
        self.start_module("proxy", "boot")
        code, reason = OK, ""
        if not self.proxy.wait_ready(max(30.0, cfg.supervisor.backoff_seconds * 4)):
            code, reason = maintain.PROXY_DOWN, "sing-box 没有在限定时间内就绪"
        else:
            self._write_state()   # 让等待中的 `norain start` 尽快返回
            if cfg.monitor.enabled:
                code = self.monitor.verify(cfg.monitor.recovery_threshold)
                reason = self.monitor.last.reason if self.monitor.last else ""
                self.start_module("monitor", "boot")
        self._boot_info.update({"test_code": code, "test_meaning": MEANING.get(code, "代理进程无法维持"),
                                "passed": code == OK})
        self.phase = RUNNING_PHASE
        if code == OK:
            self.log.info("boot.test_passed")
            if cfg.maintain.watchdog:
                self.activate_keepalive()
        else:
            self.log.error("boot.test_failed", code=code, reason=reason)
            if code != 100:
                self.maintainer.notify(code, reason)   # 交给自维持模块：修复，修不好就阻断
        self.start_module("maintain", "boot")

    def _shutdown(self) -> None:
        self.phase = BLOCKED if self.phase == BLOCKED else STOPPING
        for name in ("maintain", "monitor", "routing", "proxy"):
            mod = self.modules.get(name)
            if mod is not None:
                try:
                    mod.stop()
                except Exception:  # noqa: BLE001
                    pass
        # 用户要求停止或已进入阻断时，看门狗不应再活着；其他情况（例如本进程被系统结束）留着它
        if get_desired(self.paths.desired) != RUNNING or block.is_active(self.paths):
            maintain.kill_watchdog(self.paths)
        for f in (self.paths.runner, self.paths.status_file, self.paths.stop_file):
            f.unlink(missing_ok=True)
        self.log.info("control.stopped", exit_code=self._exit_code, phase=self.phase)

    def run(self) -> int:
        paths = self.paths0
        if self.autostart and get_desired(paths.desired) != RUNNING:
            return EXIT_OK   # 用户手动 stop 过：开机自启动时不拉起
        other = read_json(paths.runner) or {}
        if other.get("pid") != os.getpid() and pid_alive(other.get("pid")):
            raise NorainError(f"已经有一个 Norain 在运行（PID {other['pid']}）", exit_code=EXIT_CONFLICT,
                              module="control")
        paths.run_dir.mkdir(parents=True, exist_ok=True)
        paths.stop_file.unlink(missing_ok=True)
        write_json(paths.runner, {"pid": os.getpid(), "child_pid": None, "ready": False, "phase": BOOT})
        try:
            self._boot_info = boot.pre_start(paths)   # 处于阻断模式时先恢复为非阻断模式
            self._prepare()
            if self.cfg.proxy.traffic_mode == "tun" and not osutil.is_admin():
                raise NorainError("TUN 模式需要管理员权限", exit_code=EXIT_PERMISSION, module="control",
                                  hint="用管理员 / root 运行，或把 proxy.traffic_mode 改为 mixed")
            check_ports_free(generate.listeners(self.cfg))
        except NorainError as e:
            record_error(paths.last_error, e.business_code or BIZ_PROCESS_EXITED, e.message)
            paths.runner.unlink(missing_ok=True)
            raise
        if self._boot_info.get("was_blocked"):
            self.log.info("boot.block_released")
        try:
            signal.signal(signal.SIGTERM, lambda *_: self._stop.set())
            signal.signal(signal.SIGINT, lambda *_: self._stop.set())
        except ValueError:
            pass
        self._build_modules()
        try:
            self._autostart_registered = boot.registered()
        except Exception:  # noqa: BLE001
            self._autostart_registered = None
        self.log.info("control.started", traffic_mode=self.cfg.proxy.traffic_mode,
                      protocol=self.cfg.proxy.protocol, active=self.active, mode=self.cfg.app.mode)
        try:
            self._boot_sequence()
            next_state = 0.0
            while not self._stop.wait(0.5):
                if paths.stop_file.exists():
                    break
                self._serve()
                self._tick_reload()
                self._tick_selection()
                self._tick_rules()
                if time.monotonic() >= next_state:
                    next_state = time.monotonic() + 2
                    self._write_state()
        finally:
            self._shutdown()
        return self._exit_code


def read_status(paths: Paths) -> dict | None:
    """命令行读取各模块的运行情况。内控制进程不在时返回 None。"""
    info = read_json(paths.runner) or {}
    if not pid_alive(info.get("pid")):
        return None
    return read_json(paths.status_file)


def module_names() -> tuple[str, ...]:
    return MODULES

