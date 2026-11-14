"""守护模块：`norain-server run` 的前台守护进程。职责边界见 docs/decisions/0012 的修订。"""

from __future__ import annotations

from dataclasses import dataclass

from norain_core import singbox
from norain_core.errors import NorainError
from norain_core.secrets import Secret
from norain_core.supervisor import Listener, Spec, Supervisor, check_ports_free, record_error

from . import cert as certmod
from . import generate
from .model import ServerConfig, load_config
from .paths import Paths


@dataclass
class Prepared:
    cfg: ServerConfig
    paths: Paths
    secret: Secret
    binary: singbox.BinaryInfo
    cert: certmod.CertStatus
    applied: generate.ApplyResult | None


def listeners(cfg: ServerConfig) -> list[Listener]:
    out: list[Listener] = []
    if cfg.protocols.hysteria2.enabled:
        out.append((cfg.server.listen, "udp", cfg.protocols.hysteria2.port))
    if cfg.protocols.trojan.enabled:
        out.append((cfg.server.listen, "tcp", cfg.protocols.trojan.port))
    return out


def locate_singbox(paths: Paths) -> singbox.BinaryInfo:
    return singbox.inspect(singbox.locate(paths.singbox, defaults=(str(paths.default_singbox),)))


def need_tags(cfg: ServerConfig) -> set[str]:
    tags = {"with_quic"} if cfg.protocols.hysteria2.enabled else set()
    if cfg.tls.mode == "acme":
        tags.add("with_acme")
    return tags


def cert_status(cfg: ServerConfig, paths: Paths, *, tags: frozenset[str] | None = None,
                service_running: bool = False) -> certmod.CertStatus:
    """三种证书模式统一的检查入口。"""
    if cfg.tls.mode == "acme":
        return certmod.acme_status(cfg.server.domain, paths.acme_dir, tags=tags,
                                   service_running=service_running)
    cert_path, key_path = generate.cert_paths(cfg, paths)
    return certmod.check(cert_path, key_path, cfg.server.domain)


def firewall_ports(cfg: ServerConfig) -> list[tuple[str, int, str]]:
    """需要放行的 (协议, 端口, 用途)。只包含配置中启用的端口；acme 另需 80/tcp。"""
    out: list[tuple[str, int, str]] = []
    if cfg.protocols.hysteria2.enabled:
        out.append(("udp", cfg.protocols.hysteria2.port, "hysteria2"))
    if cfg.protocols.trojan.enabled:
        out.append(("tcp", cfg.protocols.trojan.port, "trojan"))
    if cfg.tls.mode == "acme" and ("tcp", 80) not in [(a, b) for a, b, _ in out]:
        out.append(("tcp", 80, "acme"))
    return out


def service_running(paths: Paths) -> bool:
    from .service import pick_backend
    try:
        return pick_backend(paths).status().state == "running"
    except Exception:  # noqa: BLE001 查询失败时按未运行处理，只影响一条警告
        return False


def prepare(paths: Paths, *, apply: bool = True) -> Prepared:
    """配置、秘密、证书、二进制的全部预检。apply=True 时生成并替换运行配置。"""
    cfg = load_config(paths.config)
    paths = paths.with_log_dir(cfg.logging.directory)
    secret = generate.resolve_secret(cfg)
    info = locate_singbox(paths)
    singbox.require(info, need_tags=need_tags(cfg))
    status = cert_status(cfg, paths, tags=info.tags, service_running=service_running(paths))
    status.raise_if_invalid()
    if cfg.tls.mode == "acme":
        paths.acme_dir.mkdir(parents=True, exist_ok=True)
    applied = generate.apply(cfg, secret, paths, info.path) if apply else None
    return Prepared(cfg, paths, secret, info, status, applied)


def run_foreground(paths: Paths) -> int:
    try:
        prep = prepare(paths)
        check_ports_free(listeners(prep.cfg))
    except NorainError as e:
        record_error(paths.last_error, e.business_code, e.message)
        raise
    cfg, p = prep.cfg, prep.paths
    return Supervisor(Spec(
        binary=prep.binary.path, config_json=p.current_json, config_version=prep.applied.version,
        listeners=listeners(cfg), check_interval=cfg.service.check_interval_seconds,
        restart_limit=cfg.service.restart_limit, backoff=cfg.service.restart_backoff_seconds,
        log_file=p.log_file, log_max_bytes=cfg.logging.max_size_mb * 1024 * 1024,
        log_keep=cfg.logging.retain_files, log_level=cfg.logging.level,
        runner_file=p.runner, last_error_file=p.last_error, stop_file=p.stop_file,
        reload_file=p.reload_file,
    )).run()
