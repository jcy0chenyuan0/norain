"""server.toml 配置模型和字段级校验。映射规则见 docs/decisions/0004。

加载顺序是「迁移 → 环境变量覆盖 → 字段校验 → 交叉校验」：Schema 版本策略和
逐级迁移在 ``norain_core.migrate``，本模块只取结果；迁移产生的 warning 挂在
配置对象上，由 ``migration_warnings`` 读取（服务端没有额外的取值提醒）。"""

from __future__ import annotations

import difflib
import ipaddress
import os
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator

from norain_core.errors import BIZ_CONFIG, EXIT_CONFIG, FieldError, NorainError, config_error
from norain_core.migrate import SCHEMA_VERSION, attach_warnings, migrate
from norain_core.redact import REDACTOR
from norain_core.secrets import check_private_file

Port = Field(ge=1, le=65535)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Server(_Strict):
    domain: str = ""
    listen: str = "::"

    @field_validator("listen")
    @classmethod
    def _listen_is_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("必须是 IP 地址，例如 :: 或 0.0.0.0") from None
        return v


class Hysteria2(_Strict):
    enabled: bool = True
    port: int = Field(443, ge=1, le=65535)


class Fallback(_Strict):
    host: str = "127.0.0.1"
    port: int = Port


class Trojan(_Strict):
    enabled: bool = False
    port: int = Field(443, ge=1, le=65535)
    fallback: Fallback | None = None


class Protocols(_Strict):
    hysteria2: Hysteria2 = Hysteria2()
    trojan: Trojan = Trojan()


class Auth(_Strict):
    credential_ref: str = ""
    password: str = ""


class Tls(_Strict):
    mode: Literal["acme", "manual", "self-signed"] = "manual"
    certificate: str = ""
    private_key: str = ""
    email: str = ""               # acme：注册邮箱，可留空
    acme_provider: str = ""       # acme：留空为 letsencrypt，可写 zerossl 或 https://… 目录地址


class Service(_Strict):
    check_interval_seconds: float = Field(30, ge=1, le=3600)
    restart_limit: int = Field(3, ge=0, le=100)
    restart_backoff_seconds: float = Field(2, ge=0, le=300)


class Logging(_Strict):
    directory: str = ""
    level: Literal["debug", "info", "warn", "error"] = "info"
    max_size_mb: int = Field(20, ge=1, le=1024)
    retain_files: int = Field(5, ge=1, le=100)


WARP_DOMAINS = ["claude.ai", "claude.com", "anthropic.com", "anthropic.ai",
                "claudeusercontent.com", "cla.st"]


class Warp(_Strict):
    """把指定域名或目标地址从本机 WARP（Cloudflare Zero Trust Client 的 socks5）出去。

    原来的服务端就是这么干的（claude/anthropic 走 WARP，其余直连）；不配就不产生路由规则。

    ip_cidr 用于「服务端只拿到 IP」的场景：客户端 TUN 模式下，sing-box 1.13+ 移除了
    sniff_override_destination，只有嗅探（route action sniff）而无覆盖，转发给服务端的
    目标仍是 IP，domain_suffix 匹配不到。此时按目标 IP 段命中 WARP 才能保住分流。
    """
    address: str = "127.0.0.1:40000"
    domains: list[str] = Field(default_factory=lambda: list(WARP_DOMAINS))
    ip_cidr: list[str] = Field(default_factory=list)   # 目标 IP 段（TUN 场景兜底）


class Routing(_Strict):
    warp: Warp | None = None


class ServerConfig(_Strict):
    _config_warnings: list[str] = PrivateAttr(default_factory=list)
    schema_version: int = Field(SCHEMA_VERSION, alias="schema")
    server: Server = Server()
    protocols: Protocols = Protocols()
    auth: Auth = Auth()
    tls: Tls = Tls()
    routing: Routing = Routing()
    service: Service = Service()
    logging: Logging = Logging()


_ENV_OVERRIDES = {
    "NORAIN_DOMAIN": ("server", "domain", str),
    "NORAIN_HY2_PORT": ("protocols", "hysteria2", "port", int),
    "NORAIN_TROJAN_PORT": ("protocols", "trojan", "port", int),
    "NORAIN_CERT_MODE": ("tls", "mode", str),
    "NORAIN_ACME_EMAIL": ("tls", "email", str),
    # 密码本身不写进模型，改成 credential_ref，避免 status / 日志把环境变量
    # 内容当成配置里的明文密码，同时保证环境变量优先于 TOML 中的旧来源。
    "NORAIN_PASSWORD": ("auth", "credential_ref", str),
}

_TYPE_MESSAGES = {
    "missing": "缺少必填字段",
    "extra_forbidden": "未知字段",
    "int_parsing": "必须是整数",
    "int_type": "必须是整数",
    "bool_type": "必须是 true 或 false",
    "bool_parsing": "必须是 true 或 false",
    "string_type": "必须是字符串",
    "model_type": "必须是一个表（[section]）",
    "model_attributes_type": "必须是一个表（[section]）",
}


def _known_names(model: type[BaseModel], out: set[str]) -> set[str]:
    for name, f in model.model_fields.items():
        out.add(f.alias or name)
        for sub in (f.annotation, *getattr(f.annotation, "__args__", ())):
            if isinstance(sub, type) and issubclass(sub, BaseModel):
                _known_names(sub, out)
    return out


_KNOWN = _known_names(ServerConfig, set())


def _translate(err: dict) -> FieldError:
    path = ".".join(str(p) for p in err["loc"]) or "(顶层)"
    kind = err["type"]
    msg = _TYPE_MESSAGES.get(kind)
    if kind == "extra_forbidden":
        close = difflib.get_close_matches(str(err["loc"][-1]), _KNOWN, n=1)
        if close:
            msg += f"，是不是想写 {close[0]}？"
    elif kind in ("greater_than_equal", "less_than_equal"):
        ctx = err.get("ctx", {})
        bound = ctx.get("ge", ctx.get("le"))
        msg = f"超出范围（{'不能小于' if 'ge' in ctx else '不能大于'} {bound}）"
    elif kind == "literal_error":
        msg = f"取值无效，可选：{err.get('ctx', {}).get('expected', '')}"
    elif kind == "value_error":
        msg = str(err.get("ctx", {}).get("error", err["msg"]))
    return FieldError(path, msg or err["msg"])


def _apply_env(data: dict, env, errors: list[FieldError]) -> list[str]:
    applied = []
    for var, (*keys, leaf, cast) in _ENV_OVERRIDES.items():
        raw = env.get(var)
        if raw is None or raw == "":
            continue
        try:
            value = (f"env:{var}" if var == "NORAIN_PASSWORD" else cast(raw))
        except ValueError:
            errors.append(FieldError(f"环境变量 {var}", "必须是整数"))
            continue
        node = data
        for k in keys:
            nxt = node.setdefault(k, {})
            if not isinstance(nxt, dict):
                break
            node = nxt
        else:
            if var == "NORAIN_PASSWORD":
                # 环境变量优先于 TOML，不能让旧的 auth.password 与新的来源
                # 同时存在，也不能保留一个会被 credential_ref 覆盖的旧文件引用。
                node.pop("password", None)
            node[leaf] = value
            applied.append(var)
    return applied


def _cross_checks(cfg: ServerConfig) -> list[FieldError]:
    errs: list[FieldError] = []
    p = cfg.protocols
    if not (p.hysteria2.enabled or p.trojan.enabled):
        errs.append(FieldError("protocols", "至少要启用 hysteria2 或 trojan 中的一个"))
    if not cfg.server.domain.strip():
        errs.append(FieldError("server.domain", "不能为空（证书的域名或 IP）"))
    if cfg.auth.password and cfg.auth.credential_ref:
        errs.append(FieldError("auth", "password 和 credential_ref 只能设置一个"))
    if cfg.tls.mode == "acme":
        # 最初目标：没有域名时不允许使用 acme
        domain = cfg.server.domain.strip().strip(".")
        try:
            ipaddress.ip_address(domain)
            errs.append(FieldError("tls.mode", "acme 模式需要域名，server.domain 不能是 IP 地址"))
        except ValueError:
            if domain and "." not in domain:
                errs.append(FieldError("tls.mode", "acme 模式需要可公开解析的域名"))
        if cfg.tls.certificate or cfg.tls.private_key:
            errs.append(FieldError("tls", "acme 模式下不要填写 certificate / private_key"))
        if p.trojan.enabled and p.trojan.port == 80:
            errs.append(FieldError("protocols.trojan.port",
                                   "acme 的 HTTP-01 挑战要占用 80/tcp，Trojan 不能用 80 端口"))
    if cfg.tls.mode == "manual":
        for name in ("certificate", "private_key"):
            if not getattr(cfg.tls, name):
                errs.append(FieldError(f"tls.{name}", "manual 模式下必须填写路径"))
    warp = cfg.routing.warp
    if warp is not None:
        host, _, port = warp.address.rpartition(":")
        if not host or not port.isdigit() or not 0 < int(port) < 65536:
            errs.append(FieldError("routing.warp.address", "必须是 host:port 形式，例如 127.0.0.1:40000"))
        if not warp.domains and not warp.ip_cidr:
            errs.append(FieldError("routing.warp.domains",
                                   "domains 和 ip_cidr 至少要写一个（TUN 下只有 IP，需要 ip_cidr）"))
        for e in warp.ip_cidr:
            try:
                ipaddress.ip_network(e.strip(), strict=False)
            except ValueError:
                errs.append(FieldError("routing.warp.ip_cidr", f"{e!r} 不是合法的 IP 段，例如 104.16.0.0/12"))
    return errs


def load_config(path: Path, env=None) -> ServerConfig:
    env = os.environ if env is None else env
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        raise NorainError(f"配置文件不存在：{path}", exit_code=EXIT_CONFIG, business_code=BIZ_CONFIG,
                          module="config", hint="参考 examples/server.toml 创建") from None
    except PermissionError:
        raise NorainError(f"无权读取配置文件：{path}", exit_code=4, business_code=BIZ_CONFIG,
                          module="config") from None
    except tomllib.TOMLDecodeError as e:
        raise config_error([FieldError("(TOML 语法)", str(e))]) from None

    migration = migrate(data, current=SCHEMA_VERSION, source=str(path))
    errors: list[FieldError] = []
    _apply_env(migration.data, env, errors)
    try:
        cfg = ServerConfig.model_validate(migration.data)
    except ValidationError as e:
        raise config_error(errors + [_translate(x) for x in e.errors()]) from None
    attach_warnings(cfg, migration)
    if not cfg.auth.password and not cfg.auth.credential_ref and not env.get("NORAIN_PASSWORD"):
        errors.append(FieldError("auth.credential_ref", "不能为空（使用 file:<路径>、env:<变量名> 或 NORAIN_PASSWORD）"))
    errors += _cross_checks(cfg)
    if cfg.auth.password:
        REDACTOR.register(cfg.auth.password)
        try:
            check_private_file(path, field="auth.password")
        except NorainError as e:
            errors += [FieldError(fe.path, fe.message + "（配置里直接写了密码）") for fe in e.field_errors]
    if errors:
        raise config_error(errors)
    return cfg
