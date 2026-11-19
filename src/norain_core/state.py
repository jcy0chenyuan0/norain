"""期望状态和操作锁。模型见 docs/decisions/0013。"""

from __future__ import annotations

import errno
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

from .atomic import atomic_write
from .errors import EXIT_CONFLICT, NorainError

RUNNING, STOPPED = "running", "stopped"


def read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_json(path: Path, obj: dict, *, durable: bool = True) -> None:
    """durable=False：不 fsync，用于每隔几秒就改写一次的运行状态文件。"""
    atomic_write(path, json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2).encode(),
                 durable=durable)


def get_desired(path: Path) -> str:
    """没有记录时视为 stopped：没有人要求过启动。"""
    data = read_json(path) or {}
    return data.get("desired") if data.get("desired") in (RUNNING, STOPPED) else STOPPED


def set_desired(path: Path, desired: str, *, op_id: str) -> None:
    assert desired in (RUNNING, STOPPED)
    write_json(path, {"desired": desired, "op_id": op_id,
                      "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")})


def pid_alive(pid: int) -> bool:
    # 不用 os.kill(pid, 0)：在 Windows 上它不是「探测」，会影响目标进程
    import psutil
    try:
        return pid > 0 and psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.AccessDenied:
        return True
    except psutil.Error:
        return False


def lock_holder(path: Path) -> dict | None:
    """返回有效的持锁者；锁过期或持锁进程已死时返回 None。"""
    data = read_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("pid"), int):
        return None
    if not pid_alive(data["pid"]):
        return None
    if not data.get("os_lock") and data.get("expires_at", 0) < time.time():
        return None
    return data


def _just_created(path: Path, *, within: float = 2.0) -> bool:
    try:
        return time.time() - path.stat().st_mtime < within
    except OSError:
        return False


def _try_lock(fd: int) -> bool:
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        if e.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
            raise
        return False
    return True


@contextmanager
def op_lock(path: Path, *, op: str, op_id: str, timeout: float = 120.0):
    """进程退出或描述符关闭时由操作系统释放锁；timeout 保留供旧调用方兼容。"""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    # 文件固定在状态目录旁边：重载修复会删除并重建状态目录，不能替换持锁文件。
    guard = path.parent.with_name(f".{path.parent.name}.{path.name}.guard")
    fd = os.open(guard, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        acquired = _try_lock(fd)
        holder = lock_holder(path)
        legacy_held = holder and not holder.get("os_lock")
        legacy_writing = read_json(path) is None and _just_created(path)
        if not acquired or legacy_held or legacy_writing:
            info = holder or {}
            raise NorainError(
                f"另一个操作正在进行：{info.get('op', '未知')}（操作 ID {info.get('op_id', '?')}）",
                exit_code=EXIT_CONFLICT, retryable=True, module="state", hint="稍后重试")
        # 老版本根据 PID 和 expires_at 判断持锁状态。当前版本用内核锁保证互斥。
        write_json(path, {"op": op, "op_id": op_id, "pid": os.getpid(),
                          "os_lock": True, "expires_at": 9e12}, durable=False)
        try:
            yield
        finally:
            path.unlink(missing_ok=True)
    finally:
        os.close(fd)
