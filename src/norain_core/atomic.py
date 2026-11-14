"""原子写入和备份轮换。"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path


def write_private(path: Path, data: bytes) -> None:
    """以 0600 权限写入并 fsync。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(path, 0o600)


def atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    write_private(tmp, data)
    os.replace(tmp, path)


def backup(path: Path, backup_dir: Path, *, keep: int = 5) -> Path | None:
    """把 path 复制到备份目录，保留最近 keep 份。path 不存在时返回 None。"""
    if not path.exists():
        return None
    backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    stamp = f"{time.strftime('%Y%m%dT%H%M%S')}-{time.time_ns() % 10**9:09d}"
    dest = backup_dir / f"{path.name}.{stamp}"
    shutil.copy2(path, dest)
    os.chmod(dest, 0o600)
    for stale in sorted(backup_dir.glob(f"{path.name}.*"))[:-keep]:
        stale.unlink(missing_ok=True)
    return dest


def promote(candidate: Path, current: Path, backup_dir: Path, *, keep: int = 5) -> Path | None:
    """备份 current，再用 candidate 原子替换它。返回备份路径。"""
    saved = backup(current, backup_dir, keep=keep)
    os.replace(candidate, current)
    return saved
