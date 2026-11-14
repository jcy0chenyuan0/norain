"""监控模块：低消耗、高频率地检测代理是否正常，给出错误码和报告。

检测三个方向（最初目标）：连通性（国内 / 国外）、出口 IP 位置（走代理与直连、IPv4 与 IPv6）、
DNS 解析位置。判定规则以最初目标为准（docs/decisions/0010 修订）：

  100  全网络连通性失败：本地没有联网
  301  部分网站正常、大部分失败，且查不到出口 IP → 触发阻断
  600  国内正常、国外失败，走代理查出口无返回、直连返回国内位置 → 服务器链路失效
  604  国内外都正常，走代理时 IPv4 出口在国内、IPv6 在国外 → IPv4 链路配置问题
  606  国内外都正常，走代理时 IPv6 出口在国内、IPv4 在国外 → IPv6 链路配置问题
  400  国内外都正常，走代理的出口在国内 → 检测链路 / 分流配置问题
  401  国外域名被解析到国内位置 → DNS 配置问题

去抖动：同一个错误码连续出现 failure_threshold 次才上报，连续正常 recovery_threshold 次才解除，
避免网络抖动误触发修复和阻断。
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from norain_core.log import Logger

from . import probe
from .model import ClientConfig
from .rules import Geo

OK = 0
MEANING = {
    0: "正常",
    100: "本地网络未连接",
    301: "大部分网站无法访问，且无法检测出口 IP",
    400: "走代理的出口位置在国内：检测链路或分流配置有问题",
    401: "国外域名被解析到国内位置：DNS 配置有问题",
    600: "服务器链路失效：服务器未启动或连接失败",
    604: "IPv4 链路配置问题：走代理时 IPv4 出口在国内",
    606: "IPv6 链路配置问题：走代理时 IPv6 出口在国内",
}
GUESS = {
    100: ["网线或 Wi-Fi 断开", "路由器或宽带故障", "系统网络被禁用"],
    301: ["代理链路严重不稳定或被干扰", "本地防火墙或安全软件拦截了大部分连接", "DNS 被污染"],
    400: ["分流规则把国外流量判成了直连", "黑名单或学到的名单里有不该直连的条目", "规则集文件损坏或过期"],
    401: ["DNS 没有经过代理服务器解析", "系统 DNS 被其他软件改写", "TUN 的 DNS 劫持没有生效"],
    600: ["代理服务器没有启动或已宕机", "服务器端口被封或防火墙没有放行", "密码或证书配置不匹配",
          "服务器地址或端口写错"],
    604: ["服务器的 IPv4 出口有问题", "客户端的 IPv4 流量没有进入代理"],
    606: ["服务器没有可用的 IPv6 出口", "客户端的 IPv6 流量绕过了代理（可在 [dns] 里设 strategy = \"ipv4_only\"）"],
}


@dataclass
class Round:
    at: float
    domestic: list[dict]
    foreign: list[dict]
    direct_v4: dict | None      # 直连查到的出口
    proxy_v4: dict | None       # 走代理（经过分流规则）查到的出口
    proxy_v6: dict | None
    dns_home: bool | None       # 国外测试域名是否被解析到国内；None 表示无法判断
    code: int = OK
    reason: str = ""
    elapsed_ms: float = 0.0

    def as_dict(self) -> dict:
        return {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.at)), "code": self.code,
                "meaning": MEANING.get(self.code, ""), "reason": self.reason,
                "elapsed_ms": round(self.elapsed_ms), "domestic": self.domestic, "foreign": self.foreign,
                "exit": {"direct_v4": self.direct_v4, "proxy_v4": self.proxy_v4, "proxy_v6": self.proxy_v6},
                "dns_resolves_foreign_to_home": self.dns_home}


@dataclass
class Ports:
    """本地探测入口。都为 None 表示代理没有运行：直连用裸连接，走代理的探测一律「无返回」。"""
    routed: probe.Proxy = None   # mixed-in：经过完整分流规则
    direct: probe.Proxy = None   # probe-direct：强制直连


def decide(rnd: Round, home: str) -> tuple[int, str]:
    """按最初目标的判定表得出本轮的原始错误码（未去抖动）。"""
    dom = [r["ok"] for r in rnd.domestic]
    frn = [r["ok"] for r in rnd.foreign]
    dom_ok = bool(dom) and sum(dom) * 2 >= len(dom)
    frn_ok = bool(frn) and sum(frn) * 2 >= len(frn)
    total, good = len(dom) + len(frn), sum(dom) + sum(frn)
    p4 = rnd.proxy_v4["loc"] if rnd.proxy_v4 else None
    p6 = rnd.proxy_v6["loc"] if rnd.proxy_v6 else None
    d4 = rnd.direct_v4["loc"] if rnd.direct_v4 else None
    home = home.upper()

    if good == 0 and rnd.direct_v4 is None:
        return 100, "国内外目标全部不通，直连也查不到出口"
    if dom_ok and not frn_ok and p4 is None and p6 is None:
        return 600, f"国内正常、国外失败；走代理查出口无返回，直连出口在 {d4 or '未知位置'}"
    if good * 2 < total and p4 is None and p6 is None and d4 is None:
        return 301, f"{total} 个目标只有 {good} 个可达，且无法检测出口 IP"
    if dom_ok and frn_ok:
        if p4 == home and p6 not in (None, home):
            return 604, f"走代理：IPv4 出口在 {p4}（国内），IPv6 出口在 {p6}"
        if p6 == home and p4 not in (None, home):
            return 606, f"走代理：IPv6 出口在 {p6}（国内），IPv4 出口在 {p4}"
        if p4 == home or (p4 is None and p6 == home):
            return 400, f"走代理的出口在 {home}（国内），直连出口在 {d4 or '未知位置'}"
        if rnd.dns_home is True:
            return 401, "国外测试域名被解析到了国内位置"
    return OK, ""


def run_round(cfg: ClientConfig, ports: Ports, geo: Geo | None = None) -> Round:
    """执行一轮检测。各探测并行，整轮耗时约等于一次超时。"""
    m = cfg.monitor
    t = m.timeout_seconds
    started = time.monotonic()
    proxy_up = ports.routed is not None

    def head(url: str, px: probe.Proxy, via: str) -> dict:
        return probe.http(url, proxy=px, timeout=t, via=via, method="HEAD").as_dict()

    def dns_home() -> bool | None:
        if geo is None:
            return None
        verdicts = []
        for name in m.dns_test_domains:
            ips = probe.system_resolve(name)
            if ips:
                verdicts.append(geo.any_home(ips))
        if any(v is True for v in verdicts):
            return True
        return False if verdicts and all(v is False for v in verdicts) else None

    with ThreadPoolExecutor(max_workers=12, thread_name_prefix="norain-probe") as pool:
        f_dom = [pool.submit(head, u, ports.direct, "direct") for u in m.domestic_targets]
        # 代理没有运行时，国外目标一律记为失败（不能用裸连接去试：那会暴露真实 IP）
        f_frn = [pool.submit(head, u, ports.routed, "proxy") for u in m.foreign_targets] if proxy_up else []
        f_d4 = pool.submit(probe.trace, m.trace_v4, proxy=ports.direct, timeout=t, via="direct")
        f_p4 = pool.submit(probe.trace, m.trace_v4, proxy=ports.routed, timeout=t, via="proxy") if proxy_up else None
        f_p6 = pool.submit(probe.trace, m.trace_v6, proxy=ports.routed, timeout=t, via="proxy") if proxy_up else None
        f_dns = pool.submit(dns_home) if proxy_up else None
        rnd = Round(
            at=time.time(),
            domestic=[f.result() for f in f_dom],
            foreign=([f.result() for f in f_frn] if proxy_up else
                     [{"ok": False, "target": u, "via": "proxy", "status": None, "elapsed_ms": None,
                       "error": "代理没有运行"} for u in m.foreign_targets]),
            direct_v4=f_d4.result(),
            proxy_v4=f_p4.result() if f_p4 else None,
            proxy_v6=f_p6.result() if f_p6 else None,
            dns_home=f_dns.result() if f_dns else None,
        )
    rnd.code, rnd.reason = decide(rnd, m.home_country)
    rnd.elapsed_ms = (time.monotonic() - started) * 1000
    return rnd


@dataclass
class Debounce:
    fail_n: int
    ok_n: int
    current: int = OK        # 已上报的错误码
    _pending: int = OK
    _count: int = 0
    _ok_count: int = 0

    def feed(self, raw: int) -> bool:
        """喂入一轮的原始码，返回上报的错误码是否发生变化。"""
        if raw == OK:
            self._pending, self._count = OK, 0
            if self.current == OK:
                return False
            self._ok_count += 1
            if self._ok_count >= self.ok_n:
                self.current, self._ok_count = OK, 0
                return True
            return False
        self._ok_count = 0
        if raw == self._pending:
            self._count += 1
        else:
            self._pending, self._count = raw, 1
        if self._count >= self.fail_n and self.current != raw:
            self.current = raw
            return True
        return False

    def reset(self) -> None:
        self.current = self._pending = OK
        self._count = self._ok_count = 0


class Monitor:
    """监控模块。自己的线程按间隔检测；错误码变化时回调 on_change(code, round)。"""

    name = "monitor"

    def __init__(self, cfg: ClientConfig, ports_fn: Callable[[], Ports], geo: Geo | None, log: Logger,
                 on_change: Callable[[int, Round], None] | None = None) -> None:
        self.cfg, self.ports_fn, self.geo, self.log, self.on_change = cfg, ports_fn, geo, log, on_change
        self.debounce = Debounce(cfg.monitor.failure_threshold, cfg.monitor.recovery_threshold)
        self.last: Round | None = None
        self.rounds = 0
        self._paused = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def code(self) -> int:
        return self.debounce.current

    def internet_ok(self) -> bool:
        return self.code != 100 and not (self.last and self.last.code == 100)

    def check_once(self, *, feed: bool = True) -> Round:
        """立即检测一轮。feed=False 时不影响去抖动计数（命令行的一次性检测）。"""
        with self._lock:
            rnd = run_round(self.cfg, self.ports_fn(), self.geo)
            self.last = rnd
            self.rounds += 1
            changed = self.debounce.feed(rnd.code) if feed else False
        if rnd.code:
            self.log.warn("monitor.round", code=rnd.code, reason=rnd.reason, reported=self.code)
        else:
            self.log.debug("monitor.round", code=0)
        if changed:
            self.log.warn("monitor.code_changed", code=self.code, meaning=MEANING.get(self.code, ""),
                          reason=rnd.reason)
            if self.on_change:
                self.on_change(self.code, rnd)
        return rnd

    def verify(self, rounds: int, *, gap: float = 1.0) -> int:
        """修复之后的验证：连续快速检测几轮，全部正常才算通过。返回最后看到的原始错误码。
        不经过去抖动，也不触发回调（调用方就是处理故障的那一方）。"""
        code = OK
        for i in range(max(rounds, 1)):
            with self._lock:
                rnd = run_round(self.cfg, self.ports_fn(), self.geo)
                self.last = rnd
                self.rounds += 1
            code = rnd.code
            if code != OK:
                return code
            if i + 1 < rounds and self._stop.wait(gap):
                break
        return code

    # 自维持模块发起修复期间暂停监控，避免修复过程中的抖动被当成新的故障
    def pause(self) -> None:
        self._paused.set()

    def resume(self, *, reset: bool = True) -> None:
        if reset:
            self.debounce.reset()
        self._paused.clear()

    @property
    def paused(self) -> bool:
        return self._paused.is_set()

    def _run(self) -> None:
        while not self._stop.is_set():
            if not self._paused.is_set():
                try:
                    self.check_once()
                except Exception as e:  # noqa: BLE001 探测器自身出错不能让模块退出
                    self.log.error("monitor.failed", error=str(e))
            if self._stop.wait(self.cfg.monitor.interval_seconds):
                break

    def start(self) -> None:
        if self.alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="norain-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(self.cfg.monitor.timeout_seconds * 3 + 5)

    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> dict:
        return {"state": ("paused" if self.paused else "running") if self.alive() else "stopped",
                "code": self.code, "meaning": MEANING.get(self.code, ""), "rounds": self.rounds,
                "last_result": self.last.as_dict() if self.last else None}


def report_text(rnd: Round) -> str:
    """给人看的检测报告。"""
    d = rnd.as_dict()
    lines = [f"错误码：{rnd.code}（{MEANING.get(rnd.code, '未知')}）"]
    if rnd.reason:
        lines.append(f"依据：{rnd.reason}")
    for title, rows in (("国内连通性（直连）", d["domestic"]), ("国外连通性（走代理）", d["foreign"])):
        ok = sum(1 for r in rows if r["ok"])
        lines.append(f"{title}：{ok}/{len(rows)}")
        lines += [f"  {'✓' if r['ok'] else '✗'} {r['target']}"
                  + (f"  {r['elapsed_ms']} ms" if r["ok"] else f"  {r['error']}") for r in rows]
    for label, key in (("直连出口 IPv4", "direct_v4"), ("代理出口 IPv4", "proxy_v4"), ("代理出口 IPv6", "proxy_v6")):
        e = d["exit"][key]
        lines.append(f"{label}：{e['ip'] + '（' + (e['loc'] or '?') + '）' if e else '无返回'}")
    lines.append("DNS：" + {True: "国外域名被解析到国内（异常）", False: "国外域名解析在国外（正常）",
                           None: "无法判断（没有 GeoIP 规则集或代理没有运行）"}[rnd.dns_home])
    if rnd.code in GUESS:
        lines.append("可能原因：")
        lines += [f"  · {g}" for g in GUESS[rnd.code]]
    return "\n".join(lines)
