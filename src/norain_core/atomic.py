"""原子写入和备份轮换。"""

from __future__ import annotations

import os
import shutil
import threading
import time
from pathlib import Path

_BINARY = getattr(os, "O_BINARY", 0)   # Windows 上不加它，os.open 得到的是文本模式的描述符


def write_private(path: Path, data: bytes, *, durable: bool = True) -> None:
    """以 0600 权限写入。durable=True 时 fsync（配置、秘密等掉电后必须完整的文件）。"""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY
    try:
        fd = os.open(path, flags, 0o600)
    except FileNotFoundError:   # 目录通常已经存在：只在缺失时才创建，省掉每次写入前的 mkdir
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        if durable:
            os.fsync(fd)
        if os.name == "posix":
            os.fchmod(fd, 0o600)   # 文件已存在时 os.open 的 mode 不生效
    finally:
        os.close(fd)


def replace(src: Path, dst: Path, *, attempts: int = 6) -> None:
    """os.replace。Windows 上目标文件正被别的进程读取时会短暂报 PermissionError，重试几次。"""
    for n in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if os.name != "nt" or n + 1 == attempts:
                raise
            time.sleep(0.02 * (n + 1))


def atomic_write(path: Path, data: bytes, *, durable: bool = True) -> None:
    """写临时文件再原子替换。durable=False 用于高频改写的状态文件（丢了可以重建，不值得 fsync）。"""
    # 临时文件名带线程 ID：同一进程的两个线程同时写同一个文件时不会互相踩临时文件
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
    try:
        write_private(tmp, data, durable=durable)
        replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


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
    replace(candidate, current)
    return saved
