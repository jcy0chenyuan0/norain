"""server.toml 配置模型和字段级校验。映射规则见 docs/decisions/0004。"""

from __future__ import annotations

import difflib
import ipaddress
import os
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from norain_core.errors import BIZ_CONFIG, EXIT_CONFIG, FieldError, NorainError, config_error
from norain_core.redact import REDACTOR
from norain_core.secrets import check_private_file

SCHEMA_VERSION = 1
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


class ServerConfig(_Strict):
    schema_version: int = Field(SCHEMA_VERSION, alias="schema")
    server: Server = Server()
    protocols: Protocols = Protocols()
    auth: Auth = Auth()
    tls: Tls = Tls()
    service: Service = Service()
    logging: Logging = Logging()


_ENV_OVERRIDES = {
    "NORAIN_DOMAIN": ("server", "domain", str),
    "NORAIN_HY2_PORT": ("protocols", "hysteria2", "port", int),
    "NORAIN_TROJAN_PORT": ("protocols", "trojan", "port", int),
    "NORAIN_CERT_MODE": ("tls", "mode", str),
    "NORAIN_ACME_EMAIL": ("tls", "email", str),
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
            value = cast(raw)
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
            node[leaf] = value
            applied.append(var)
    return applied


def _cross_checks(cfg: ServerConfig) -> list[FieldError]:
    errs: list[FieldError] = []
    p = cfg.protocols
    if not (p.hysteria2.enabled or p.trojan.enabled):
        errs.append(FieldError("protocols", "至少要启用 hysteria2 或 trojan 中的一个"))
    if cfg.schema_version != SCHEMA_VERSION:
        errs.append(FieldError("schema", f"不支持的配置版本 {cfg.schema_version}，本程序支持 {SCHEMA_VERSION}"))
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

    errors: list[FieldError] = []
    _apply_env(data, env, errors)
    try:
        cfg = ServerConfig.model_validate(data)
    except ValidationError as e:
        raise config_error(errors + [_translate(x) for x in e.errors()]) from None
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
