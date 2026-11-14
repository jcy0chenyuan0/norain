"""期望状态和操作锁。模型见 docs/decisions/0013。"""

from __future__ import annotations

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


def write_json(path: Path, obj: dict) -> None:
    atomic_write(path, json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2).encode())


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
    except psutil.Error:
        return False


def lock_holder(path: Path) -> dict | None:
    """返回有效的持锁者；锁过期或持锁进程已死时返回 None。"""
    data = read_json(path)
    if not data:
        return None
    if data.get("expires_at", 0) < time.time() or not pid_alive(int(data.get("pid", 0))):
        return None
    return data


@contextmanager
def op_lock(path: Path, *, op: str, op_id: str, timeout: float = 120.0):
    """互斥执行 start/stop/restart 等操作。失效的锁会被接管。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"op": op, "op_id": op_id, "pid": os.getpid(),
                          "expires_at": time.time() + timeout}).encode()
    for attempt in (1, 2):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            holder = lock_holder(path)
            if holder or attempt == 2:
                raise NorainError(
                    f"另一个操作正在进行：{(holder or {}).get('op', '未知')}"
                    f"（操作 ID {(holder or {}).get('op_id', '?')}）",
                    exit_code=EXIT_CONFLICT, retryable=True, module="state",
                    hint="稍后重试") from None
            path.unlink(missing_ok=True)  # 接管失效的锁
    with os.fdopen(fd, "wb") as f:
        f.write(payload)
    try:
        yield
    finally:
        mine = read_json(path)
        if mine and mine.get("op_id") == op_id:
            path.unlink(missing_ok=True)
