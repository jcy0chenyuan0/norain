"""客户端守护的入口：`norain run` 的预检，以及在后台启动 / 停止它的后端。

`norain run` 运行的是内控制模块（control.Controller），代理、分流、监控、自维持都是它里面的组件。
"""

from __future__ import annotations

from dataclasses import dataclass

from norain_core import singbox
from norain_core.apply import ApplyResult
from norain_core.daemonctl import DetachedBackend
from norain_core.secrets import Secret
from norain_core.supervisor import Listener

from . import generate
from .model import ClientConfig, load_config
from .paths import Paths


@dataclass
class Prepared:
    cfg: ClientConfig
    paths: Paths
    secret: Secret
    binary: singbox.BinaryInfo
    applied: ApplyResult | None


def listeners(cfg: ClientConfig) -> list[Listener]:
    return generate.listeners(cfg)


def locate_singbox(paths: Paths) -> singbox.BinaryInfo:
    path = singbox.locate(paths.singbox, defaults=(str(paths.bundled_singbox),),
                          env_name="NORAIN_SINGBOX")
    return singbox.inspect(path)


def prepare(paths: Paths, *, apply: bool = True) -> Prepared:
    """配置、秘密、二进制的全部预检。apply=True 时生成并替换运行配置（先过 sing-box check）。"""
    cfg = load_config(paths.config)
    paths = paths.with_log_dir(cfg.logging.directory)
    secret = generate.resolve_secret(cfg)
    info = locate_singbox(paths)
    singbox.require(info, need_tags={"with_quic"} if "hysteria2" in cfg.protocols else set())
    applied = generate.apply(cfg, secret, paths, info.path) if apply else None
    return Prepared(cfg, paths, secret, info, applied)


def backend(paths: Paths) -> DetachedBackend:
    return DetachedBackend(module="norain", runner_file=paths.runner,
                           last_error_file=paths.last_error, stop_file=paths.stop_file,
                           log_dir=paths.log_dir)


def run_foreground(paths: Paths, *, autostart: bool = False) -> int:
    from .control import Controller
    return Controller(paths, autostart=autostart).run()
