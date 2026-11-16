"""cfg.toml → sing-box JSON：代理模块和分流模块的数据面配置。

字段依据 sing-box 1.14 官方文档（不使用 1.14 已弃用的字段：DNS 规则的 strategy、
independent_cache、TUN 的 stack 等），尚未经真实 sing-box check 验证。

结构：
  入站  mixed-in（本地代理）、tun-in（traffic_mode = tun）、
        probe-direct / probe-<协议>（监控和自适应选协议用的本地探测入口，不受分流规则影响）
  出站  proxy（当前使用的协议）、proxy-alt（auto 时的另一个协议）、direct
  路由  探测入口 → 私有地址直连 → 白名单 → 黑名单 → 学到的名单 → 规则集（国内直连）→ 默认动作
  DNS   白名单和默认动作走代理侧 DNS；黑名单和国内规则集走国内 DNS；代理侧失败不回落国内（防泄漏）
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from norain_core import apply as core_apply
from norain_core.secrets import Secret, resolve
from norain_core.state import read_json
from norain_core.supervisor import Listener

from .model import KNOWN_RULE_SETS, PROTOCOLS, SCHEMA_VERSION, ClientConfig, split_entries
from .paths import Paths

dumps, version_of = core_apply.dumps, core_apply.version_of

LOOPBACK = "127.0.0.1"


def resolve_secret(cfg: ClientConfig) -> Secret:
    if cfg.proxy.password:
        return Secret(value=cfg.proxy.password, source="config:proxy.password")
    return resolve(cfg.proxy.credential_ref, field="proxy.credential_ref")


def probe_ports(cfg: ClientConfig) -> dict[str, int]:
    """本地探测入口的端口。direct：直连；<协议>：强制走该协议的出站。"""
    base = cfg.local.probe_port
    ports = {"direct": base}
    for i, proto in enumerate(PROTOCOLS, start=1):
        if proto in cfg.protocols:
            ports[proto] = base + i
    return ports


def needs_probes(cfg: ClientConfig) -> bool:
    """监控、分流学习、自适应选协议都要用本地探测入口。"""
    return cfg.monitor.enabled or cfg.routing.learn or cfg.proxy.protocol == "auto"


def listeners(cfg: ClientConfig) -> list[Listener]:
    out: list[Listener] = [(cfg.local.listen, "tcp", cfg.local.port)]
    if needs_probes(cfg):
        out += [(LOOPBACK, "tcp", port) for port in probe_ports(cfg).values()]
    return out


def active_protocol(cfg: ClientConfig, paths: Paths | None = None) -> str:
    """当前使用的协议。auto 时取内控制模块上次选中的结果，没有记录时用 prefer。"""
    if cfg.proxy.protocol != "auto":
        return cfg.proxy.protocol
    chosen = (read_json(paths.selection) or {}).get("active") if paths else None
    return chosen if chosen in PROTOCOLS else cfg.proxy.selection.prefer


def rule_files(cfg: ClientConfig, paths: Paths | None) -> dict[str, Path]:
    """规则集标签 → 本地 .srs 文件。文件不存在的规则集直接跳过（流量落到默认动作）。"""
    out: dict[str, Path] = {}
    for rs in cfg.routing.rule_set:
        if rs in KNOWN_RULE_SETS:
            f = paths.rules_dir / f"{rs}.srs" if paths else None
        else:
            f = Path(rs).expanduser()
            rs = f.stem
        if f is not None and f.is_file():
            out[rs] = f
    return out


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _outbound(cfg: ClientConfig, protocol: str, password: str, tag: str) -> dict:
    p = cfg.proxy
    tls: dict = {"enabled": True, "server_name": p.tls.server_name or p.server}
    if protocol == "hysteria2":
        tls["alpn"] = ["h3"]
    if p.tls.certificate_path:
        tls["certificate_path"] = str(Path(p.tls.certificate_path).expanduser())
    if p.tls.insecure:
        tls["insecure"] = True
    out: dict = {"type": protocol, "tag": tag, "server": p.server, "server_port": p.port_of(protocol),
                 "password": password, "tls": tls}
    if protocol == "trojan" and p.trojan.multiplex.enabled:  # 服务端入站开了 multiplex 才可用
        m = p.trojan.multiplex
        out["multiplex"] = {"enabled": True, "protocol": m.protocol, "max_streams": m.max_streams}
    return out


def _dns_server(tag: str, address: str, *, detour: str | None, resolver: str) -> dict:
    """把 `https://host/path` 或裸 IP 转成 1.12+ 的 DNS server 写法。"""
    if _is_ip(address):
        srv: dict = {"type": "udp", "tag": tag, "server": address}
    else:
        u = urlsplit(address)
        srv = {"type": "https", "tag": tag, "server": u.hostname}
        if u.port:
            srv["server_port"] = u.port
        if u.path and u.path != "/dns-query":
            srv["path"] = u.path
        if not _is_ip(u.hostname or ""):
            srv["domain_resolver"] = resolver
    if detour:
        srv["detour"] = detour
    return srv


def _domain_match(entries: list[str]) -> dict:
    """DNS 规则只能按域名匹配，去掉名单里的 IP 条目。"""
    m = split_entries(entries)
    m.pop("ip_cidr", None)
    return m


def _dns(cfg: ClientConfig, learned: dict, geosite_tags: list[str], strategy: str) -> tuple[dict, str]:
    """返回 (dns 配置, 默认域名解析器的标签)。"""
    if cfg.dns.mode == "local":
        # 只用系统 DNS 解析代理服务器域名和直连目标；走代理的域名交给服务端解析
        return {"servers": [{"type": "local", "tag": "local"}]}, "local"

    servers = [
        {"type": "local", "tag": "local"},
        {"type": "udp", "tag": "dns-direct", "server": cfg.dns.domestic},
        _dns_server("dns-proxy", cfg.dns.proxy, detour="proxy", resolver="dns-direct"),
    ]
    rules: list[dict] = []
    hosts = learned.get("hosts") or {}
    if hosts:  # 分流模块更新过的解析结果
        servers.append({"type": "hosts", "tag": "dns-hosts", "predefined": dict(sorted(hosts.items()))})
        rules.append({"domain": sorted(hosts), "action": "route", "server": "dns-hosts"})
    if not _is_ip(cfg.proxy.server):  # 代理服务器自己的域名必须直连解析，否则死循环
        rules.append({"domain": [cfg.proxy.server.lower()], "action": "route", "server": "dns-direct"})

    def add(entries: list[str], server: str) -> None:
        m = _domain_match(entries)
        if m:
            rules.append({**m, "action": "route", "server": server})

    add(cfg.routing.proxy_domains, "dns-proxy")     # 白名单：恒用服务器侧解析
    add(cfg.routing.direct_domains, "dns-direct")   # 黑名单：国内 DNS
    add(learned.get("proxy") or [], "dns-proxy")
    add(learned.get("direct") or [], "dns-direct")
    if cfg.dns.mode == "split":
        if geosite_tags:
            rules.append({"rule_set": geosite_tags, "action": "route", "server": "dns-direct"})
        final = "dns-proxy" if cfg.routing.default_action == "proxy" else "dns-direct"
    else:  # proxy：除黑名单外全部由服务器侧解析
        final = "dns-proxy"
    return {"servers": servers, "rules": rules, "final": final, "strategy": strategy}, "dns-direct"


def build(cfg: ClientConfig, password: str, *, active: str | None = None, learned: dict | None = None,
          rules: dict[str, Path] | None = None, strategy: str | None = None) -> dict:
    """生成 sing-box 配置。

    active    当前协议（auto 时由内控制模块决定）
    learned   分流模块学到的名单：{"proxy": [...], "direct": [...], "hosts": {域名: [IP]}}
    rules     可用的规则集文件：{标签: 路径}
    strategy  DNS 的 IPv4/IPv6 策略覆盖（自维持模块处理 604/606 时使用）
    """
    learned = learned or {}
    rules = rules or {}
    active = active if active in cfg.protocols else active_protocol(cfg)
    tun = cfg.proxy.traffic_mode == "tun"

    # ---- 出站：当前协议叫 proxy，auto 时另一个叫 proxy-alt ----
    tag_of = {active: "proxy"}
    outbounds = [_outbound(cfg, active, password, "proxy")]
    for proto in cfg.protocols:
        if proto != active:
            tag_of[proto] = "proxy-alt"
            outbounds.append(_outbound(cfg, proto, password, "proxy-alt"))
    outbounds.append({"type": "direct", "tag": "direct"})

    # ---- 入站 ----
    mixed: dict = {"type": "mixed", "tag": "mixed-in", "listen": cfg.local.listen,
                   "listen_port": cfg.local.port}
    if cfg.proxy.traffic_mode == "system-proxy":
        mixed["set_system_proxy"] = True
    inbounds = [mixed]
    if tun:
        inbounds.append({"type": "tun", "tag": "tun-in", "interface_name": cfg.tun.interface_name,
                         "address": list(cfg.tun.address), "mtu": cfg.tun.mtu,
                         "auto_route": True, "strict_route": cfg.tun.strict_route})
    route_rules: list[dict] = [{"action": "sniff"}]
    if tun:
        route_rules.append({"protocol": "dns", "action": "hijack-dns"})
    if needs_probes(cfg):
        for name, port in probe_ports(cfg).items():
            inbounds.append({"type": "mixed", "tag": f"probe-{name}", "listen": LOOPBACK, "listen_port": port})
            route_rules.append({"inbound": f"probe-{name}", "action": "route",
                                "outbound": "direct" if name == "direct" else tag_of[name]})

    # ---- 路由：内部保留 → 白名单 → 黑名单 → 学到的名单 → 规则集 → 默认动作 ----
    route_rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})

    def add(entries: list[str], outbound: str) -> None:
        m = split_entries(entries)
        if m:
            route_rules.append({**m, "action": "route", "outbound": outbound})

    add(cfg.routing.proxy_domains, "proxy")
    add(cfg.routing.direct_domains, "direct")
    add(learned.get("proxy") or [], "proxy")
    add(learned.get("direct") or [], "direct")
    if rules:
        route_rules.append({"rule_set": sorted(rules), "action": "route", "outbound": "direct"})

    strategy = strategy or cfg.dns.strategy
    dns, resolver = _dns(cfg, learned, sorted(t for t in rules if t.startswith("geosite")), strategy)
    route: dict = {"rules": route_rules,
                   "final": "proxy" if cfg.routing.default_action == "proxy" else "direct",
                   "default_domain_resolver": resolver}
    if rules:
        route["rule_set"] = [{"type": "local", "tag": tag, "format": "binary", "path": str(path)}
                             for tag, path in sorted(rules.items())]
    if tun:
        route["auto_detect_interface"] = True  # 出站绑定物理网卡，避免被自己的 TUN 接管形成环路

    return {
        "log": {"level": cfg.logging.level, "timestamp": True},
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
    }


def context(cfg: ClientConfig, paths: Paths | None) -> dict:
    """从状态目录读出生成器需要的运行时输入。"""
    if paths is None:
        return {}
    from .routing import load_learned
    overrides = read_json(paths.selection) or {}
    return {"active": active_protocol(cfg, paths), "learned": load_learned(paths).for_generator(),
            "rules": rule_files(cfg, paths), "strategy": overrides.get("dns_strategy")}


def render(cfg: ClientConfig, secret: Secret, paths: Paths | None = None) -> bytes:
    return dumps(build(cfg, secret.value, **context(cfg, paths)))


def apply(cfg: ClientConfig, secret: Secret, paths: Paths, binary: Path):
    return core_apply.apply(render(cfg, secret, paths), run_dir=paths.run_dir, current=paths.current_json,
                            backups=paths.backups, meta=paths.meta_json, source=paths.config,
                            schema=SCHEMA_VERSION, binary=binary)
