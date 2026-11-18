"""自维持模块：维持代理正常运行，其他模块被杀死或异常时迅速拉起，修不好时启动阻断。

两部分：

1. Maintainer —— 内控制进程里的一个组件（线程），低开销地反复扫描：
   - 监视各模块是否在线，掉线的模块向内控制申请拉起；
   - 监控模块抛出错误码时：结束相应进程，调用修复模块（只用文件修复和内置配置修复），重启代理；
   - 修复失败时启动阻断模块。
2. 看门狗 —— 独立进程（`norain _watchdog`），与内控制进程互相拉起：
   内控制进程被杀，看门狗把它拉起；看门狗被杀，Maintainer 把它拉起。

与其他模块的协同（避免互相打架）：
   - 所有拉起和结束都经内控制审批；启动测试期间内控制会拒绝本模块的拉起请求。
   - 修复期间暂停监控，修复后由本模块主动验证；这样修复过程中的抖动不会被当成新故障。
   - 任何保活方在拉起前都检查期望状态：用户 stop 之后（desired = stopped）不再拉起任何东西。
   - 有操作锁（start/stop/restart/repair 正在执行）时看门狗不动作。
   - 阻断生效后看门狗退出，不再拉起内控制进程。
   - 用户用命令行停掉的单个模块不会被自动拉起（否则停不掉）。
   - 看门狗在短时间内反复拉起仍然失败，或上次失败原因是配置无效 / 缺少 sing-box 时停止拉起。

各错误码的处理：
   100  本地没有联网：不是代理的问题，不修复也不阻断，等网络恢复。
   301  直接进入阻断（最初目标）。
   600  重启代理；自适应协议时切换到另一个协议；仍不行 → 文件修复 + 内置配置修复 → 阻断。
   604/606  调整 DNS 的 IPv4/IPv6 策略并重启；仍不行 → 修复 → 阻断。
   400/401  清掉学到的名单并重新生成配置；仍不行 → 修复 → 阻断。
   140（代理进程无法维持）  修复 → 阻断。
"""

from __future__ import annotations

import collections
import os
import threading
import time
from typing import TYPE_CHECKING

import psutil

from norain_core import osutil
from norain_core.daemonctl import alive as pid_alive
from norain_core.daemonctl import runner_info
from norain_core.errors import BIZ_BINARY_MISSING, BIZ_CONFIG, EXIT_OK, NorainError
from norain_core.log import Logger, RotatingFile
from norain_core.state import RUNNING, get_desired, lock_holder, read_json, write_json

from . import block, repair
from .monitor import MEANING, OK
from .paths import Paths

if TYPE_CHECKING:
    from .control import Controller

PROXY_DOWN = 140           # 代理进程无法维持（沿用服务端「sing-box 进程退出」的业务码）
WATCHED = ("routing", "proxy", "monitor")
PULL_WINDOW, PULL_LIMIT = 600, 5


class Maintainer:
    name = "maintain"

    def __init__(self, ctl: "Controller", log: Logger) -> None:
        self.ctl, self.log = ctl, log
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pending: tuple[int, str] | None = None
        self._reported_100 = False
        self.pulls = 0
        self.last_result: dict | None = None

    # 监控模块在错误码变化时调用（在监控线程里，只记下来，由本模块的线程处理）
    def notify(self, code: int, reason: str) -> None:
        self._pending = (code, reason)

    def tick(self) -> None:
        ctl = self.ctl
        if ctl.phase != "running":
            return  # 启动测试、修复、停止、阻断期间不介入
        if get_desired(ctl.paths.desired) != RUNNING:
            return

        # 1. 模块在线情况
        for name in WATCHED:
            mod = ctl.modules.get(name)
            if mod is None or name in ctl.user_stopped or mod.alive():
                continue
            if name == "proxy" and ctl.proxy.failed:
                self.escalate(PROXY_DOWN, "sing-box 连续重启失败，监督器已放弃")
                return
            ok, why = ctl.start_module(name, "maintain")
            self.pulls += 1
            self.log.warn("maintain.pulled", module=name, ok=ok, detail=why)

        # 2. 互拉保活：监控通过之后才激活
        if ctl.cfg.maintain.watchdog and "maintain" not in ctl.user_stopped:
            if not ctl.keepalive and ctl.monitor_code() == OK:
                ctl.activate_keepalive()
            elif ctl.keepalive and not watchdog_alive(ctl.paths):
                spawn_watchdog(ctl.paths)
                self.pulls += 1
                self.log.warn("maintain.pulled", module="watchdog")

        # 3. 监控模块抛出的错误码
        pending, self._pending = self._pending, None
        code, reason = pending if pending else (ctl.monitor_code(), "")
        if code == OK:
            self._reported_100 = False
            return
        if code == 100:
            if not self._reported_100:
                self._reported_100 = True
                self.log.warn("maintain.no_internet", note="本地网络未连接，等待恢复；不修复也不阻断")
            return
        self.escalate(code, reason or MEANING.get(code, ""))

    # ---- 修复升级 ----

    def _light_fix(self, code: int) -> list[str]:
        """第一轮：不动文件的轻量处理。"""
        ctl, done = self.ctl, []
        if code == 600 and ctl.selector is not None:
            new = ctl.switch_protocol("maintain", "当前协议链路失效")
            if new:
                done.append(f"切换协议为 {new}")
        elif code == 606:
            ctl.set_override(dns_strategy="ipv4_only")
            done.append("DNS 改为只用 IPv4（IPv6 链路异常）")
        elif code == 604:
            ctl.set_override(dns_strategy="prefer_ipv6")
            done.append("DNS 改为优先 IPv6（IPv4 链路异常）")
        elif code in (400, 401):
            ctl.clear_learned()
            done.append("清除自动学到的名单")
        return done

    def escalate(self, code: int, reason: str) -> str:
        """处理一个故障：先阻断 → 修复 → 验证 → 修好就解除，修不好就保持阻断。

        返回 recovered / aborted / blocked / failed。
        阻断先行的原因：修复要花几秒到几十秒，这段时间流量会回落直连、暴露真实 IP。
        只放行代理服务器的修复窗口见 block.engage(repairing=True)。
        """
        ctl, cfg = self.ctl, self.ctl.cfg
        result = {"code": code, "reason": reason, "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                  "attempts": [], "outcome": ""}
        self.log.error("maintain.fault", code=code, meaning=MEANING.get(code, "代理进程无法维持"), reason=reason)
        ctl.enter_repair(code)
        outcome = "failed"
        try:
            blocked = self._block_first(code, reason)
            if blocked and ctl.stop_requested:
                outcome = "aborted"   # 阻断期间用户要求停止：保持阻断退出，不继续修
            else:
                outcome, code = self._repair_rounds(code, reason, result)
                if outcome == "recovered":
                    if blocked:
                        self._unblock_after_repair(ctl.paths)
                    else:
                        self.log.warn("maintain.recovered_without_block", note="阻断没有生效，修复成功")
                elif blocked:
                    outcome = "blocked"
                ctl.request_shutdown(blocked=outcome == "blocked", code=code)
        finally:
            result["outcome"] = outcome
            self.last_result = result
            ctl.leave_repair(outcome)
            self._pending = None
            self.log.warn("maintain.fault_handled", code=code, outcome=outcome)
        return outcome

    def _block_first(self, code: int, reason: str) -> bool:
        """立刻进入阻断。返回是否已阻断；失败时明确告知用户流量可能直连，但修复仍然要做。"""
        ctl, cfg = self.ctl, self.ctl.cfg
        if not cfg.maintain.block_on_failure:
            return False
        try:
            block.engage(cfg, ctl.paths, code=code, reason=reason, log=self.log, repairing=True)
            return True
        except NorainError as e:
            # 阻断没有生效必须明确告诉用户：此时流量可能直连，但修复仍然要做
            self.log.error("maintain.block_failed", error=e.message, hint=e.hint)
            osutil.popup("Norain：代理失效且阻断没有生效",
                         f"代理无法恢复（错误码 {code}），并且无法进入阻断模式：{e.message}\n"
                         "当前流量可能直连，请立即检查。")
            return False

    def _repair_rounds(self, code: int, reason: str, result: dict) -> tuple[str, int]:
        """在阻断状态下修复。返回 (outcome, 最终错误码)。

        最终错误码要回传给调用方：修复过程中可能看到新的错误码，弹窗和 last_error
        应该报最后那个，而不是最初触发的那一个。
        """
        ctl, cfg = self.ctl, self.ctl.cfg
        outcome = "failed"
        attempts = 0 if code == 301 else cfg.maintain.repair_attempts  # 301 直接阻断，不修
        for n in range(1, attempts + 1):
            if ctl.stop_requested:
                outcome = "aborted"
                break
            actions: list[str] = []
            if n == 1 and code != PROXY_DOWN:
                actions += self._light_fix(code)
            else:  # 自维持模块只用文件修复和内置配置修复
                ctl.stop_module("proxy", "maintain")
                for rep in (repair.repair_files(ctl.paths, self.log),
                            repair.repair_builtin(ctl.paths, self.log)):
                    actions += rep.actions + [f"未修好：{p}" for p in rep.problems]
                ctl.clear_learned()   # 内置配置修复清掉了磁盘上的名单，内存里的也要一起清
                ctl.set_override(dns_strategy=None)
            ok, why = ctl.restart_proxy("maintain", f"修复错误码 {code}（第 {n} 轮）")
            actions.append("重启代理" + ("" if ok else f"失败：{why}"))
            ready = ok and ctl.proxy.wait_ready(30)
            seen = ctl.verify(cfg.monitor.recovery_threshold) if ready else PROXY_DOWN
            result["attempts"].append({"round": n, "actions": actions, "code_after": seen})
            self.log.warn("maintain.repair_round", round=n, actions=actions, code_after=seen)
            if seen == OK:
                outcome = "recovered"
                break
            if seen == 100:  # 修复途中本地断网：不是代理的问题，不能据此继续修
                outcome = "aborted"
                break
            code = seen if seen in MEANING or seen == PROXY_DOWN else code
        return outcome, code

    def _unblock_after_repair(self, paths) -> None:
        """修好了：把临时放行范围收回，然后解除阻断。

        tighten 失败时必须中止：此时系统里可能一条阻断规则都不剩，再去 release 会把
        残缺状态当成功清掉。宁可把错误暴露给用户，也不假装恢复完成。
        """
        try:
            block.tighten(paths, log=self.log)
        except NorainError as e:
            self.log.error("maintain.tighten_failed", error=e.message, hint=e.hint,
                           note="中止解除阻断，保持当前阻断状态")
            osutil.popup("Norain：代理已修复，但恢复网络失败",
                         f"代理已经恢复，但收紧放行范围时出错：{e.message}\n"
                         + (e.hint or "") + "\n网络可能仍处于限制状态，请检查。")
            return
        try:
            block.release(paths, log=self.log)
            self.log.info("maintain.unblocked", note="修复成功，已恢复正常网络")
        except NorainError as e:
            # 代理已修好、放行范围也收回了，但规则没删掉 —— 用户会以为 norain 坏了，
            # 必须明确告诉他网络为什么还断着、怎么手工恢复
            self.log.error("maintain.unblock_failed", error=e.message, hint=e.hint)
            osutil.popup("Norain：代理已修复，但网络仍未恢复",
                         f"代理已经恢复，但删除阻断规则失败：{e.message}\n"
                         + (e.hint or "") + "\n在管理员终端运行 norain block off 重试。")

    # ---- 模块生命周期 ----

    def _run(self) -> None:
        interval = self.ctl.cfg.maintain.scan_interval_seconds
        while not self._stop.wait(interval):
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001 自维持自身不能因为一次扫描出错而退出
                self.log.error("maintain.tick_failed", error=repr(e))

    def start(self) -> None:
        if self.alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="norain-maintain", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(5)

    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> dict:
        return {"state": "running" if self.alive() else "stopped", "pulls": self.pulls,
                "watchdog_alive": watchdog_alive(self.ctl.paths), "keepalive": self.ctl.keepalive,
                "last_result": self.last_result}


# ---- 看门狗进程 ----------------------------------------------------------------

def _watchdog_pid(paths: Paths) -> int | None:
    pid = (read_json(paths.watchdog_file) or {}).get("pid")
    if not pid_alive(pid):
        return None
    try:
        if "_watchdog" not in " ".join(psutil.Process(pid).cmdline()):
            return None  # PID 已被别的进程复用
    except psutil.Error:
        return None
    return pid


def watchdog_alive(paths: Paths) -> bool:
    return _watchdog_pid(paths) is not None


def spawn_watchdog(paths: Paths) -> None:
    osutil.spawn_detached([osutil.python_exe(windowless=True), "-m", "norain", "_watchdog"],
                          log_file=paths.log_dir / "watchdog.out")


def kill_watchdog(paths: Paths) -> bool:
    pid = _watchdog_pid(paths)
    if pid is None:
        paths.watchdog_file.unlink(missing_ok=True)
        return False
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(5)
        except psutil.TimeoutExpired:
            proc.kill()
    except psutil.Error:
        pass
    paths.watchdog_file.unlink(missing_ok=True)
    return True


def watchdog_main(paths: Paths) -> int:
    """看门狗主循环。内控制进程不在了就把它拉起；该停的时候自己退出。"""
    from .model import load_config
    other = _watchdog_pid(paths)
    if other and other != os.getpid():
        return EXIT_OK  # 已经有一个看门狗
    try:
        cfg = load_config(paths.config)
        paths = paths.with_log_dir(cfg.logging.directory)
        interval = cfg.maintain.scan_interval_seconds
    except NorainError:
        interval = 5.0
    log = Logger("watchdog", sink=RotatingFile(paths.log_file, max_bytes=20 << 20, keep=5), stderr=False)
    write_json(paths.watchdog_file, {"pid": os.getpid(), "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
    pulls: collections.deque[float] = collections.deque()
    log.info("watchdog.started", interval=interval)
    try:
        while True:
            time.sleep(interval)
            if (read_json(paths.watchdog_file) or {}).get("pid") != os.getpid():
                return EXIT_OK  # 被新的看门狗取代，或状态文件被清掉（卸载、停止）
            if get_desired(paths.desired) != RUNNING:
                log.info("watchdog.exit", reason="期望状态是 stopped")
                return EXIT_OK
            if block.is_active(paths):
                log.info("watchdog.exit", reason="已进入阻断模式")
                return EXIT_OK
            if lock_holder(paths.lock) or runner_info(paths.runner):
                continue
            last = read_json(paths.last_error) or {}
            if last.get("business_code") in (BIZ_CONFIG, BIZ_BINARY_MISSING):
                log.error("watchdog.exit", reason="配置无效或缺少 sing-box，拉起也没用", last_error=last)
                return EXIT_OK
            now = time.monotonic()
            while pulls and now - pulls[0] > PULL_WINDOW:
                pulls.popleft()
            if len(pulls) >= PULL_LIMIT:
                log.error("watchdog.exit", reason=f"{PULL_WINDOW} 秒内已拉起 {PULL_LIMIT} 次仍然失败")
                return EXIT_OK
            pulls.append(now)
            log.warn("watchdog.pull", target="controller")
            osutil.spawn_detached([osutil.python_exe(windowless=True), "-m", "norain", "run"],
                                  log_file=paths.log_dir / "daemon.out")
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not runner_info(paths.runner):
                time.sleep(0.5)
    finally:
        if (read_json(paths.watchdog_file) or {}).get("pid") == os.getpid():
            paths.watchdog_file.unlink(missing_ok=True)
