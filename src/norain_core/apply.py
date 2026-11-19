"""「生成候选 → sing-box check → 备份 → 原子替换」流程，客户端和服务端共用。"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from . import __version__ as GENERATOR_VERSION
from . import atomic, singbox
from .state import write_json


def dumps(doc: dict) -> bytes:
    """确定性序列化：同一输入必须得到字节级相同的输出。"""
    return (json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def version_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


@dataclass(frozen=True)
class ApplyResult:
    version: str
    changed: bool
    backup: Path | None


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def check_only(data: bytes, run_dir: Path, binary: Path) -> None:
    """只校验，不替换当前配置。"""
    _private_dir(run_dir)
    tmp = run_dir / f".validate-{os.getpid()}.json"
    atomic.write_private(tmp, data)
    try:
        singbox.check(binary, tmp)
    finally:
        tmp.unlink(missing_ok=True)


def apply(data: bytes, *, run_dir: Path, current: Path, backups: Path, meta: Path, source: Path,
          schema: int, binary: Path) -> ApplyResult:
    """校验失败时抛出异常，当前配置保持不变。"""
    _private_dir(run_dir)
    old_current = current.read_bytes() if current.exists() else None
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    candidate = run_dir / f".candidate-{os.getpid()}.json"
    try:
        atomic.write_private(candidate, data)
        singbox.check(binary, candidate)
        if old_current == data:
            return ApplyResult(version_of(data), False, None)
        saved = atomic.promote(candidate, current, backups)
    finally:
        candidate.unlink(missing_ok=True)
    # 元数据写失败时把当前配置和元数据一起退回：否则调用方收到失败，
    # 运行配置却已经是新的，后续重启就会读到调用方以为没有生效的配置。
    try:
        write_json(meta, {
            "config_version": version_of(data),
            "generator_version": GENERATOR_VERSION,
            "singbox_version": singbox.PINNED_VERSION,
            "norain_schema": schema,
            "source_sha256": source_hash,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        })
    except OSError:
        if saved is not None:
            atomic.replace(saved, current)
        else:
            current.unlink(missing_ok=True)
        raise
    return ApplyResult(version_of(data), True, saved)
