"""cfg.toml 配置模型。没有实现的取值在校验时明确拒绝（目前只有 traffic_mode = "transparent"）。

加载顺序是「迁移 → 字段校验 → 交叉校验」：Schema 版本策略和逐级迁移在
``norain_core.migrate``，本模块只取结果；迁移产生的 warning 挂在配置对象上，
由 ``warnings_of`` 统一展示。

名单的含义（docs/decisions/0007）：
  routing.proxy_domains        白名单：强制走代理，DNS 由服务器侧解析
  routing.direct_domains       黑名单：强制直连，DNS 用国内服务器
  routing.isolation_allowlist  蓝名单：阻断模式下仍允许的连接
  monitor.foreign_targets / domestic_targets  监控测试名单
"""

from __future__ import annotations

import difflib
import ipaddress
import os
import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator

from norain_core.errors import BIZ_CONFIG, EXIT_CONFIG, FieldError, NorainError, config_error
from norain_core.migrate import (SCHEMA_VERSION, MigrationResult, attach_warnings, migrate,
                                migration_warnings)
from norain_core.redact import REDACTOR
from norain_core.secrets import check_private_file

from . import defaults

PROTOCOLS = ("hysteria2", "trojan")
KNOWN_RULE_SETS = ("geosite-cn", "geoip-cn")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class App(_Strict):
    mode: Literal["normal", "safe"] = "normal"   # safe：不开机自启动，只能手动启动
    auto_start: bool = True                       # normal 模式下是否注册开机自启动


class Local(_Strict):
    listen: str = "127.0.0.1"
    port: int = Field(2080, ge=1, le=65535)
    probe_port: int = Field(2090, ge=1, le=65530)  # 监控用的本地探测入口，占用连续 3 个端口

    @field_validator("listen")
    @classmethod
    def _ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("必须是 IP 地址，例如 127.0.0.1") from None
        return v


class ProtoPort(_Strict):
    port: int = Field(443, ge=1, le=65535)


class Multiplex(_Strict):
    """trojan 的多路复用，**默认关闭**。

    sing-box 1.7 起客户端 mux 走 sp.mux.sing-box.arpa，服务端必须在**入站**上显式开启
    multiplex 才接受。原来那套服务端（同样是 1.14.4）没有开，2026-11-15 实测：客户端开
    mux 时 trojan 立刻失败（HTTP 000，服务端日志 "global multiplex is deprecated …
    enable multiplex in Inbound fields instead"），关掉立刻通（200）。
    只有自建服务端的入站也开了 multiplex 时才值得打开。

    hysteria2 不走这里：它是 QUIC 上的原生协议，sing-box 不支持也不需要对它多路复用。
    """
    enabled: bool = False
    protocol: Literal["smux", "yamux", "h2mux"] = "smux"
    max_streams: int = Field(8, ge=1, le=128)


class Trojan(ProtoPort):
    multiplex: Multiplex = Multiplex()


class ProxyTls(_Strict):
    server_name: str = ""          # 留空时用 proxy.server
    certificate_path: str = ""     # 服务端用自签证书时，填这张证书的路径
    insecure: bool = False         # 跳过证书校验，不安全，仅调试


class Selection(_Strict):
    """protocol = "auto" 时的自适应参数（docs/decisions/0009）。"""
    interval_seconds: float = Field(60, ge=5)
    failure_threshold: int = Field(3, ge=1)          # 当前协议连续失败这么多次就切换
    latency_ratio: float = Field(1.3, ge=1.0)        # 延迟中位数差到这个倍数……
    latency_margin_ms: float = Field(100, ge=0)      # ……并且差值超过这么多毫秒才切换
    cooldown_seconds: float = Field(600, ge=0)       # 两次切换的最小间隔（当前协议完全不可用时除外）
    prefer: Literal["hysteria2", "trojan"] = "hysteria2"
    test_url: str = "https://www.gstatic.com/generate_204"


class Proxy(_Strict):
    protocol: Literal["auto", "hysteria2", "trojan"] = "hysteria2"
    server: str = ""
    credential_ref: str = ""
    password: str = ""
    traffic_mode: Literal["mixed", "system-proxy", "tun", "transparent"] = "mixed"
    hysteria2: ProtoPort = ProtoPort()
    trojan: Trojan = Trojan()
    tls: ProxyTls = ProxyTls()
    selection: Selection = Selection()

    @property
    def port(self) -> int:
        return self.port_of(self.protocol if self.protocol != "auto" else self.selection.prefer)

    def port_of(self, protocol: str) -> int:
        return getattr(self, protocol).port


class Tun(_Strict):
    interface_name: str = "norain0"
    address: list[str] = ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
    mtu: int = Field(9000, ge=576, le=65535)
    strict_route: bool = True


class Routing(_Strict):
    proxy_domains: list[str] = list(defaults.PROXY_DOMAINS)            # 白名单：强制走代理
    direct_domains: list[str] = list(defaults.DIRECT_DOMAINS)          # 黑名单：强制直连
    isolation_allowlist: list[str] = list(defaults.ISOLATION_ALLOWLIST)  # 蓝名单：阻断模式下仍允许
    rule_set: list[str] = list(KNOWN_RULE_SETS)   # 判为「国内 → 直连」的规则集；文件缺失时自动跳过
    default_action: Literal["proxy", "direct"] = "proxy"
    learn: bool = True                   # 按最初目标的试连流程自动改判并加入名单
    update_interval_hours: float = Field(24, ge=0)   # 规则集自更新间隔，0 表示不自动更新
    allow_lan_in_isolation: bool = True


class Dns(_Strict):
    mode: Literal["local", "split", "proxy"] = "split"
    domestic: str = "223.5.5.5"                          # 国内 DNS（直连）
    proxy: str = "https://1.1.1.1/dns-query"             # 经代理服务器访问的国外 DNS
    domestic_doh: str = "https://223.5.5.5/resolve"      # 分流判断用的 JSON 查询接口（直连）
    public_doh: str = "https://1.1.1.1/dns-query"        # 分流判断用的 JSON 查询接口（经代理）
    strategy: Literal["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"] = "prefer_ipv4"
    cache_ttl_seconds: int = Field(300, ge=0)            # 学到的解析结果（hosts 覆盖）的保留时间
    fake_ip: bool = False                                # 只对走代理的域名用 fake-ip（见 ADR 0006）
    fake_ip_range: str = "198.18.0.0/15"                 # fake-ip v4 段（RFC 2544 保留段）
    fake_ip_range_v6: str = ""                           # fake-ip v6 段，空表示不启用


class Monitor(_Strict):
    enabled: bool = True
    interval_seconds: float = Field(30, ge=1)
    timeout_seconds: float = Field(5, ge=1, le=60)
    failure_threshold: int = Field(3, ge=1)
    recovery_threshold: int = Field(2, ge=1)
    home_country: str = "CN"             # 「国内位置」的国家代码
    domestic_targets: list[str] = ["https://www.baidu.com", "https://www.qq.com", "https://www.taobao.com"]
    foreign_targets: list[str] = ["https://www.google.com/generate_204", "https://www.youtube.com",
                                  "https://github.com", "https://www.wikipedia.org"]
    trace_v4: str = "https://1.1.1.1/cdn-cgi/trace"
    trace_v6: str = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
    dns_test_domains: list[str] = ["www.google.com", "www.youtube.com"]


class Maintain(_Strict):
    scan_interval_seconds: float = Field(5, ge=1, le=300)
    repair_attempts: int = Field(2, ge=1, le=10)   # 每个故障最多尝试几轮修复，之后进入阻断
    block_on_failure: bool = True
    watchdog: bool = True                          # 与看门狗进程互拉保活


class SupervisorCfg(_Strict):
    check_interval_seconds: float = Field(30, ge=1, le=3600)
    restart_limit: int = Field(3, ge=0, le=100)
    backoff_seconds: float = Field(5, ge=0, le=300)


class Logging(_Strict):
    directory: str = ""
    level: Literal["debug", "info", "warn", "error"] = "info"
    max_size_mb: int = Field(20, ge=1, le=1024)
    retain_files: int = Field(5, ge=1, le=100)


class ClientConfig(_Strict):
    _config_warnings: list[str] = PrivateAttr(default_factory=list)
    schema_version: int = Field(SCHEMA_VERSION, alias="schema")
    app: App = App()
    local: Local = Local()
    proxy: Proxy = Proxy()
    tun: Tun = Tun()
    routing: Routing = Routing()
    dns: Dns = Dns()
    monitor: Monitor = Monitor()
    maintain: Maintain = Maintain()
    supervisor: SupervisorCfg = SupervisorCfg()
    logging: Logging = Logging()

    @property
    def protocols(self) -> tuple[str, ...]:
        """本配置会用到的协议。auto 时两套都生成。"""
        return PROTOCOLS if self.proxy.protocol == "auto" else (self.proxy.protocol,)

    @property
    def autostart_wanted(self) -> bool:
        return self.app.mode == "normal" and self.app.auto_start


_MESSAGES = {
    "missing": "缺少必填字段", "extra_forbidden": "未知字段", "int_parsing": "必须是整数",
    "int_type": "必须是整数", "bool_type": "必须是 true 或 false", "bool_parsing": "必须是 true 或 false",
    "string_type": "必须是字符串", "list_type": "必须是列表", "float_type": "必须是数字",
    "float_parsing": "必须是数字",
    "model_type": "必须是一个表（[section]）", "model_attributes_type": "必须是一个表（[section]）",
}


def _known(model: type[BaseModel], out: set[str]) -> set[str]:
    for name, f in model.model_fields.items():
        out.add(f.alias or name)
        if isinstance(f.annotation, type) and issubclass(f.annotation, BaseModel):
            _known(f.annotation, out)
    return out


_KNOWN = _known(ClientConfig, set())


def _translate(err: dict) -> FieldError:
    path = ".".join(str(p) for p in err["loc"]) or "(顶层)"
    kind, ctx = err["type"], err.get("ctx", {})
    msg = _MESSAGES.get(kind)
    if kind == "extra_forbidden":
        close = difflib.get_close_matches(str(err["loc"][-1]), _KNOWN, n=1)
        msg += f"，是不是想写 {close[0]}？" if close else ""
    elif kind in ("greater_than_equal", "less_than_equal"):
        msg = f"超出范围（{'不能小于' if 'ge' in ctx else '不能大于'} {ctx.get('ge', ctx.get('le'))}）"
    elif kind == "literal_error":
        msg = f"取值无效，可选：{ctx.get('expected', '')}"
    elif kind == "value_error":
        msg = str(ctx.get("error", err["msg"]))
    return FieldError(path, msg or err["msg"])


# ---- 名单条目 ------------------------------------------------------------------

def split_entries(entries: list[str]) -> dict[str, list[str]]:
    """把名单条目分成 sing-box 规则字段：
    `example.com` → domain_suffix；`full:example.com` → domain；IP 或 CIDR → ip_cidr。"""
    out: dict[str, list[str]] = {"domain": [], "domain_suffix": [], "ip_cidr": []}
    for raw in entries:
        e = raw.strip().lower()
        if not e:
            continue
        if e.startswith("full:"):
            out["domain"].append(e[5:])
            continue
        try:
            ipaddress.ip_network(e, strict=False)
            out["ip_cidr"].append(e)
        except ValueError:
            out["domain_suffix"].append(e.lstrip("."))
    return {k: v for k, v in out.items() if v}


def _entry_error(e: str) -> str | None:
    s = e.strip()
    body = s[5:] if s.lower().startswith("full:") else s
    if not body:
        return "条目不能为空"
    if any(c.isspace() for c in body) or "://" in body:
        return f"{e!r} 不是域名、IP 或 CIDR（不要带 http:// 和路径）"
    return None


def entry_key(e: str) -> str:
    s = e.strip().lower()
    return s[5:] if s.startswith("full:") else s.lstrip(".")


def _cross_checks(cfg: ClientConfig) -> list[FieldError]:
    errs: list[FieldError] = []
    if cfg.proxy.traffic_mode == "transparent":
        errs.append(FieldError("proxy.traffic_mode",
                               "transparent 尚未实现；全局接管请用 tun，其余可用 mixed 或 system-proxy"))
    if not cfg.proxy.server.strip():
        errs.append(FieldError("proxy.server", "不能为空（代理服务器的域名或 IP）"))
    if not cfg.proxy.password and not cfg.proxy.credential_ref and not os.environ.get("NORAIN_PASSWORD"):
        errs.append(FieldError("proxy.credential_ref", "不能为空（使用 file:<路径>、env:<变量名> 或 NORAIN_PASSWORD）"))
    if cfg.proxy.password and cfg.proxy.credential_ref:
        errs.append(FieldError("proxy", "password 和 credential_ref 只能设置一个"))
    cert = cfg.proxy.tls.certificate_path
    if cert and not Path(cert).expanduser().is_file():
        errs.append(FieldError("proxy.tls.certificate_path", f"文件不存在：{cert}"))

    for name in ("proxy_domains", "direct_domains", "isolation_allowlist"):
        for e in getattr(cfg.routing, name):
            msg = _entry_error(e)
            if msg:
                errs.append(FieldError(f"routing.{name}", msg))
    both = {entry_key(e) for e in cfg.routing.proxy_domains} & {entry_key(e) for e in cfg.routing.direct_domains}
    if both:  # 同一条目同时在白名单和黑名单：直接报错，不做隐式优先
        errs.append(FieldError("routing", "同时出现在 proxy_domains 和 direct_domains 中：" + "、".join(sorted(both))))
    for rs in cfg.routing.rule_set:
        if rs not in KNOWN_RULE_SETS and not (rs.endswith(".srs") and Path(rs).expanduser().is_file()):
            errs.append(FieldError("routing.rule_set",
                                   f"{rs!r} 不是内置规则集（{'、'.join(KNOWN_RULE_SETS)}），也不是存在的 .srs 文件"))

    try:
        ipaddress.ip_address(cfg.dns.domestic)
    except ValueError:
        errs.append(FieldError("dns.domestic", "必须是 IP 地址，例如 223.5.5.5"))
    for name in ("proxy", "domestic_doh", "public_doh"):
        value = getattr(cfg.dns, name)
        u = urlsplit(value)
        try:
            u.port          # 非法端口（例如 :bad）会让 urlsplit 抛 ValueError
        except ValueError:
            errs.append(FieldError(f"dns.{name}", "端口不是有效的数字"))
            continue
        is_ip = False
        try:
            ipaddress.ip_address(value)
            is_ip = name == "proxy"  # dns.proxy 允许直接写 IP（UDP）
        except ValueError:
            pass
        if not is_ip and (u.scheme != "https" or not u.hostname):
            errs.append(FieldError(f"dns.{name}", "必须是 https://… 地址" + ("或 IP 地址" if name == "proxy" else "")))
    for name in ("domestic_targets", "foreign_targets"):
        for t in getattr(cfg.monitor, name):
            if urlsplit(t).scheme not in ("http", "https"):
                errs.append(FieldError(f"monitor.{name}", f"{t!r} 必须是 http(s):// 地址"))
    if cfg.monitor.enabled and not (cfg.monitor.domestic_targets and cfg.monitor.foreign_targets):
        errs.append(FieldError("monitor", "启用监控时 domestic_targets 和 foreign_targets 都不能为空"))
    ports = [cfg.local.port, *range(cfg.local.probe_port, cfg.local.probe_port + 3)]
    if len(set(ports)) != len(ports):
        errs.append(FieldError("local.probe_port", "探测端口（连续 3 个）不能和 local.port 重叠"))
    for a in cfg.tun.address:
        try:
            ipaddress.ip_interface(a)
        except ValueError:
            errs.append(FieldError("tun.address", f"{a!r} 不是带前缀长度的地址，例如 172.19.0.1/30"))
    return errs


def parse(data: dict, *, source: str = "cfg.toml") -> ClientConfig:
    """迁移并校验一份已经解析成字典的配置（不检查文件权限）。"""
    migration = migrate(data, current=SCHEMA_VERSION, source=source)
    try:
        cfg = ClientConfig.model_validate(migration.data)
    except ValidationError as e:
        raise config_error([_translate(x) for x in e.errors()]) from None
    attach_warnings(cfg, migration)
    errs = _cross_checks(cfg)
    if errs:
        raise config_error(errs)
    return cfg


def migrate_doc(data: dict, *, source: str = "cfg.toml") -> MigrationResult:
    """只做 Schema 迁移、不校验字段：写盘前用它拿到要落盘的数据。

    命令行改配置时会重写整个文件，顺手把迁移结果写进去，否则「缺少 schema」
    的 warning 每次加载都会再出现一遍。
    """
    return migrate(data, current=SCHEMA_VERSION, source=source)


def read_raw(path: Path) -> dict:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise NorainError(f"配置文件不存在：{path}", exit_code=EXIT_CONFIG, business_code=BIZ_CONFIG,
                          module="config", hint="运行 norain install，或参考 examples/cfg.toml 创建") from None
    except PermissionError:
        raise NorainError(f"无权读取配置文件：{path}", exit_code=4, business_code=BIZ_CONFIG,
                          module="config") from None
    except tomllib.TOMLDecodeError as e:
        raise config_error([FieldError("(TOML 语法)", str(e))]) from None


def load_config(path: Path) -> ClientConfig:
    cfg = parse(read_raw(path), source=str(path))
    if cfg.proxy.password:
        REDACTOR.register(cfg.proxy.password)
        try:
            check_private_file(path, field="proxy.password")
        except NorainError as e:
            raise config_error([FieldError(fe.path, fe.message + "（配置里直接写了密码）")
                                for fe in e.field_errors]) from None
    return cfg


def warnings_of(cfg: ClientConfig) -> list[str]:
    """这份配置值得提醒用户的全部事情：迁移 warning 加上取值、运行模式的提示。"""
    out = migration_warnings(cfg)
    if cfg.proxy.tls.insecure:
        out.append("proxy.tls.insecure = true：不校验服务端证书，连接可能被中间人劫持")
    if cfg.local.listen not in ("127.0.0.1", "::1"):
        out.append(f"本地代理监听在 {cfg.local.listen}，局域网内其他设备也能使用它，且没有认证")
    if cfg.proxy.traffic_mode != "tun":
        out.append(f"traffic_mode = {cfg.proxy.traffic_mode}：只有使用本地代理的程序才走代理，不是全局接管；"
                   "DNS 分流只在 tun 模式下对全部程序生效")
    if not cfg.monitor.enabled:
        out.append("监控已关闭：自维持模块无法发现链路故障，也不会触发阻断")
    if os.name == "nt" and (cfg.proxy.password or cfg.proxy.credential_ref.startswith("file:")):
        out.append("Windows 上不检查密码文件的访问权限，请自行确认其他用户读不到它")
    return out
