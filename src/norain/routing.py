"""分流模块的运行时部分：按最初目标的四步流程判断一个域名该走哪条路，并把结论学进名单。

静态的分流（白名单、黑名单、规则集、默认动作）由 generate.py 写进 sing-box 配置，sing-box 在
进程内完成路由，Norain 无法逐个请求介入。所以「试连 → 改判 → 加入白名单」做成事后学习：

  1. 从 sing-box 日志里发现访问失败的域名（Router.feed）；
  2. 对这个域名执行最初目标的流程（Classifier.classify）；
  3. 结论写入 learned.json，由内控制模块重新生成配置并重载 sing-box。

最初目标的流程与本实现的对应：
  第 2 步 查白名单/黑名单            → 已被名单覆盖的域名不再判断
  第 3 步 本地 DNS 解析并判断国内外   → 国内 DNS 解析 + geosite-cn（判不出时用 geoip-cn）
     A 国内：直连试连 → 不行则代理试连（成功就改判国外、加入白名单）→ 再不行用公共 DNS 重新解析
     B 国外：代理试连 → 不行则由服务器侧解析并更新本地解析结果
     C 都不行 → 第 4 步
  第 4 步 GeoIP 判断；查不到就交给服务器解析并走代理（默认动作）
  特殊情况：本地没有联网时不判断；哪条路都不通时记为「目标不可达」（网站维护或 DNS 故障），不学习。

sing-box 的日志格式是按 1.x 的常见输出推定的，尚未用真实日志验证。
"""

from __future__ import annotations

import queue
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable

from norain_core.log import Logger
from norain_core.state import read_json, write_json

from . import probe
from .model import ClientConfig, entry_key
from .paths import Paths
from .rules import Geo

UNREACHABLE_TTL = 1800       # 「目标不可达」的记忆时间
RETRY_COOLDOWN = 600         # 同一域名两次判断的最小间隔
FAILURES_BEFORE_CLASSIFY = 2

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_CONN = re.compile(r"\[(\d+)[^\]]*\]\s+outbound/[\w-]+\[([^\]]+)\]: outbound (?:packet )?connection to "
                   r"\[?([^\s\]]+?)\]?:(\d+)\s*$")
_ERR = re.compile(r"\bERROR\b.*?\[(\d+)[^\]]*\]")


# ---- 学到的名单 ----------------------------------------------------------------

@dataclass
class Learned:
    proxy: dict[str, dict] = field(default_factory=dict)       # 域名 → {at, reason}
    direct: dict[str, dict] = field(default_factory=dict)
    hosts: dict[str, dict] = field(default_factory=dict)       # 域名 → {ips, expires}
    unreachable: dict[str, float] = field(default_factory=dict)  # 域名 → 记忆到期时间

    def for_generator(self) -> dict:
        now = time.time()
        return {"proxy": sorted(self.proxy), "direct": sorted(self.direct),
                "hosts": {d: v["ips"] for d, v in self.hosts.items()
                          if v.get("expires", 0) > now and v.get("ips")}}

    def prune(self) -> bool:
        now = time.time()
        before = (len(self.hosts), len(self.unreachable))
        self.hosts = {d: v for d, v in self.hosts.items() if v.get("expires", 0) > now}
        self.unreachable = {d: t for d, t in self.unreachable.items() if t > now}
        return before[0] != len(self.hosts)  # hosts 变化才需要重新生成配置

    def as_dict(self) -> dict:
        return {"proxy": self.proxy, "direct": self.direct, "hosts": self.hosts,
                "unreachable": self.unreachable}


def load_learned(paths: Paths) -> Learned:
    data = read_json(paths.learned) or {}
    return Learned(**{k: data.get(k) or {} for k in ("proxy", "direct", "hosts", "unreachable")})


def save_learned(paths: Paths, learned: Learned) -> None:
    paths.routing_dir.mkdir(parents=True, exist_ok=True)
    write_json(paths.learned, learned.as_dict())


def covered(domain: str, entries) -> bool:
    """域名是否被名单里的某一条覆盖（后缀匹配，`full:` 精确匹配）。"""
    domain = domain.lower().rstrip(".")
    for raw in entries:
        e = raw.strip().lower()
        if e.startswith("full:"):
            if domain == e[5:]:
                return True
        elif domain == entry_key(e) or domain.endswith("." + entry_key(e)):
            return True
    return False


# ---- 判断流程 ------------------------------------------------------------------

@dataclass
class Verdict:
    domain: str
    decision: str          # proxy | direct | unreachable | skip
    steps: list[str]
    changed: bool = False  # 学到了新东西，需要重新生成配置

    def as_dict(self) -> dict:
        return {"domain": self.domain, "decision": self.decision, "changed": self.changed,
                "steps": self.steps}


class Classifier:
    def __init__(self, cfg: ClientConfig, paths: Paths, geo: Geo, *, direct: probe.Proxy,
                 proxy: probe.Proxy, internet_ok: Callable[[], bool] = lambda: True) -> None:
        """direct / proxy：强制直连和强制走代理的本地探测入口。"""
        self.cfg, self.paths, self.geo = cfg, paths, geo
        self.direct, self.proxy, self.internet_ok = direct, proxy, internet_ok
        self.timeout = cfg.monitor.timeout_seconds

    def _try(self, domain: str, via: str) -> bool:
        return probe.reachable(domain, proxy=self.direct if via == "direct" else self.proxy,
                               timeout=self.timeout, via=via).ok

    def _try_ips(self, ips: list[str], via: str) -> bool:
        px = self.direct if via == "direct" else self.proxy
        return any(probe.tcp(ip, 443, proxy=px, timeout=self.timeout) for ip in ips[:3])

    def classify(self, domain: str, learned: Learned) -> Verdict:
        domain = domain.lower().rstrip(".")
        steps: list[str] = []
        r, cfg = self.cfg.routing, self.cfg

        def learn(bucket: str, reason: str, ips: list[str] | None = None) -> Verdict:
            other = "direct" if bucket == "proxy" else "proxy"
            getattr(learned, other).pop(domain, None)
            getattr(learned, bucket)[domain] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "reason": reason}
            if ips:  # 更新解析结果
                learned.hosts[domain] = {"ips": ips[:4], "expires": time.time() + max(cfg.dns.cache_ttl_seconds, 60)}
                steps.append(f"更新解析结果：{', '.join(ips[:4])}")
            learned.unreachable.pop(domain, None)
            steps.append(f"结论：{'走代理（加入白名单）' if bucket == 'proxy' else '直连（加入黑名单）'}——{reason}")
            return Verdict(domain, bucket, steps, changed=True)

        # 特殊情况：本地没有联网
        if not self.internet_ok():
            return Verdict(domain, "skip", ["本地网络未连接，不做判断"])
        # 第 2 步：名单
        if covered(domain, r.proxy_domains):
            return Verdict(domain, "proxy", ["在白名单中：走代理，由服务器侧解析"])
        if covered(domain, r.direct_domains):
            return Verdict(domain, "direct", ["在黑名单中：直连，用国内 DNS 解析"])
        if learned.unreachable.get(domain, 0) > time.time():
            return Verdict(domain, "unreachable", ["此前判定为目标不可达，暂不重试"])

        # 第 3 步：本地（国内）DNS 解析，判断国内还是国外
        local_ips = probe.doh(cfg.dns.domestic_doh, domain, proxy=self.direct, timeout=self.timeout)
        steps.append(f"国内 DNS 解析：{', '.join(local_ips) or '无结果'}")
        home = self.geo.domain_is_home(domain)
        if home is None and local_ips:
            home = self.geo.any_home(local_ips)
        steps.append("判断：" + {True: "国内", False: "国外", None: "无法判断"}[home])
        best_ips = local_ips

        if home is True:  # A
            if self._try(domain, "direct"):
                steps.append("国内分流（直连）访问正常")
                if domain in learned.proxy or r.default_action == "proxy":
                    return learn("direct", "解析在国内且直连可用")
                return Verdict(domain, "direct", steps)
            steps.append("直连访问失败")
            if self._try(domain, "proxy"):
                return learn("proxy", "解析在国内但只有代理能访问，改判为国外")
            steps.append("代理访问也失败，改用公共 DNS 解析")
            pub_ips = probe.doh(cfg.dns.public_doh, domain, proxy=self.proxy, timeout=self.timeout)
            steps.append(f"公共 DNS 解析：{', '.join(pub_ips) or '无结果'}")
            if pub_ips and set(pub_ips) != set(local_ips):
                best_ips = pub_ips
                if self._try_ips(pub_ips, "direct"):
                    return learn("direct", "公共 DNS 的解析结果直连可用", pub_ips)
                if self._try_ips(pub_ips, "proxy"):
                    return learn("proxy", "公共 DNS 的解析结果经代理可用", pub_ips)
        elif home is False:  # B
            if self._try(domain, "proxy"):
                steps.append("国外分流（代理）访问正常")
                if domain in learned.direct or r.default_action == "direct":
                    return learn("proxy", "解析在国外且代理可用")
                return Verdict(domain, "proxy", steps)
            steps.append("代理访问失败，向服务器侧发起解析")
            srv_ips = probe.doh(cfg.dns.public_doh, domain, proxy=self.proxy, timeout=self.timeout)
            steps.append(f"服务器侧解析：{', '.join(srv_ips) or '无结果'}")
            if srv_ips:
                best_ips = srv_ips
                if self._try_ips(srv_ips, "proxy"):
                    return learn("proxy", "服务器侧的解析结果经代理可用", srv_ips)

        # 第 4 步：GeoIP
        geo = self.geo.any_home(best_ips) if best_ips else None
        steps.append("GeoIP：" + {True: "国内", False: "国外", None: "查不到"}[geo])
        if geo is True and self._try(domain, "direct"):
            return learn("direct", "GeoIP 判定为国内且直连可用")
        if geo is not True and self._try(domain, "proxy"):
            # 查不到时交给服务器解析并走代理；默认动作本来就是代理时不需要额外记一条
            if geo is False or r.default_action == "direct":
                return learn("proxy", "GeoIP 判定为国外且代理可用" if geo is False else "查不到归属，交给服务器解析")
            steps.append("结论：按默认动作走代理")
            return Verdict(domain, "proxy", steps)
        # 特殊情况：服务器问题（DNS 连不上 / 网站本身在维护）
        learned.unreachable[domain] = time.time() + UNREACHABLE_TTL
        steps.append("直连和代理都无法访问：可能是网站自身维护或 DNS 故障，不修改名单")
        return Verdict(domain, "unreachable", steps)


# ---- 模块 ----------------------------------------------------------------------

class Router:
    """分流模块：消费 sing-box 日志里的失败记录，判断并学习。"""

    name = "routing"

    def __init__(self, cfg: ClientConfig, paths: Paths, classifier: Classifier, log: Logger,
                 on_change: Callable[[], None]) -> None:
        self.cfg, self.paths, self.classifier, self.log, self.on_change = cfg, paths, classifier, log, on_change
        self.learned = load_learned(paths)
        self._learn = bool(cfg.routing.learn)   # feed() 每行日志都读它，取成普通属性
        self._q: queue.Queue[str] = queue.Queue(maxsize=256)
        self._conns: OrderedDict[str, tuple[str, str]] = OrderedDict()   # 连接 ID → (出站, 主机)
        self._fails: dict[str, int] = {}
        self._last: dict[str, float] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_result: dict | None = None
        self.classified = 0

    # sing-box 的每一行输出都会经过这里（在日志泵线程里），必须很快返回
    def feed(self, line: str) -> None:
        if not self._learn:
            return
        # 绝大多数日志行两种都不是：先用子串检查排除，再动用正则
        is_conn = "connection to " in line
        if not is_conn and "ERROR" not in line:
            return
        if "\x1b" in line:
            line = _ANSI.sub("", line)
        if is_conn:
            m = _CONN.search(line)
            if m:
                cid, tag, host = m.group(1), m.group(2), m.group(3).lower()
                self._conns[cid] = (tag, host)
                if len(self._conns) > 2000:
                    self._conns.popitem(last=False)
                return
        m = _ERR.search(line)
        if not m:
            return
        tag, host = self._conns.pop(m.group(1), (None, None))
        if tag == "proxy-alt":
            # Auto mode uses proxy-alt for the non-selected protocol. It is
            # still a proxied path and must participate in post-failure learning.
            tag = "proxy"
        if not host or tag not in ("direct", "proxy") or _looks_like_ip(host):
            return
        self._fails[host] = self._fails.get(host, 0) + 1
        if len(self._fails) > 2000:
            self._fails.clear()
        now = time.time()
        if self._fails[host] >= FAILURES_BEFORE_CLASSIFY and now - self._last.get(host, 0) > RETRY_COOLDOWN:
            if len(self._last) > 2000:   # 只保留还在冷却期内的记录，长期运行时不会无限增长
                self._last = {h: t for h, t in self._last.items() if now - t <= RETRY_COOLDOWN}
            self._last[host] = now
            self._fails.pop(host, None)
            try:
                self._q.put_nowait(host)
            except queue.Full:
                pass

    def check(self, domain: str) -> Verdict:
        """立即判断一个域名（命令行和内控制都可以调用）。"""
        v = self.classifier.classify(domain, self.learned)
        self.classified += 1
        self.last_result = v.as_dict()
        save_learned(self.paths, self.learned)
        self.log.info("routing.classified", **v.as_dict())
        return v

    def _run(self) -> None:
        next_prune = time.monotonic() + 300
        while not self._stop.is_set():
            try:
                domain = self._q.get(timeout=1)
            except queue.Empty:
                domain = None
            changed = False
            if domain:
                try:
                    changed = self.check(domain).changed
                except Exception as e:  # noqa: BLE001 单个域名判断出错不能让模块退出
                    self.log.error("routing.classify_failed", domain=domain, error=str(e))
            if time.monotonic() >= next_prune:
                next_prune = time.monotonic() + 300
                if self.learned.prune():
                    save_learned(self.paths, self.learned)
                    changed = True
            if changed:
                self.on_change()

    def start(self) -> None:
        if self.alive():
            return
        self._stop.clear()
        self.learned = load_learned(self.paths)
        self._thread = threading.Thread(target=self._run, name="norain-routing", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(self.cfg.monitor.timeout_seconds * 8 + 5)

    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> dict:
        return {"state": "running" if self.alive() else "stopped", "learn": self.cfg.routing.learn,
                "learned_proxy": len(self.learned.proxy), "learned_direct": len(self.learned.direct),
                "hosts_overrides": len(self.learned.hosts), "queued": self._q.qsize(),
                "classified": self.classified, "last_result": self.last_result}


def _looks_like_ip(host: str) -> bool:
    return ":" in host or host.replace(".", "").isdigit()
