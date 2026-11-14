"""在后台启动、停止和查询守护进程（`python -m <模块> run`），客户端和服务端共用。"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import psutil

from .errors import BIZ_PROCESS_EXITED, EXIT_EXTERNAL, EXIT_PERMISSION, EXIT_TIMEOUT, NorainError
from .state import read_json


@dataclass
class ServiceStatus:
    backend: str
    state: str  # running | stopped | failed
    pid: int | None = None
    child_pid: int | None = None
    restarts: int = 0
    outer_restarts: int | None = None


def alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.Error:
        return False


def runner_info(runner_file: Path) -> dict:
    info = read_json(runner_file) or {}
    return info if alive(info.get("pid")) else {}


def _same_or_child(pid: int | None, launched: int) -> bool:
    """pid 是我们启动的进程，或者是它的直接子进程（Windows 虚拟环境的 python.exe 是转发器）。"""
    if not pid:
        return False
    if pid == launched:
        return True
    try:
        return psutil.Process(pid).ppid() == launched
    except psutil.Error:
        return False


def _kill(pid: int | None) -> None:
    try:
        if pid:
            psutil.Process(pid).kill()
    except psutil.Error:
        pass


class DetachedBackend:
    """没有外层保活：守护进程自身被结束后不会恢复。"""

    name = "detached"

    def __init__(self, *, module: str, runner_file: Path, last_error_file: Path, stop_file: Path,
                 log_dir: Path) -> None:
        self.module, self.runner_file, self.last_error_file = module, runner_file, last_error_file
        self.stop_file, self.log_dir = stop_file, log_dir

    def status(self) -> ServiceStatus:
        info = runner_info(self.runner_file)
        if info:
            return ServiceStatus(self.name, "running", info["pid"], info.get("child_pid"),
                                 info.get("restarts", 0))
        return ServiceStatus(self.name, "stopped")

    def start(self, *, timeout: float = 20.0) -> None:
        if runner_info(self.runner_file):
            return  # 幂等
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.last_error_file.unlink(missing_ok=True)
        self.stop_file.unlink(missing_ok=True)
        extra = {}
        if os.name == "nt":
            extra["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                                      | subprocess.CREATE_NO_WINDOW)
        else:
            extra["start_new_session"] = True
        with open(self.log_dir / "daemon.out", "ab") as out:
            proc = subprocess.Popen([sys.executable, "-m", self.module, "run"],
                                    stdin=subprocess.DEVNULL, stdout=out, stderr=out,
                                    close_fds=True, **extra)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rc = proc.poll()
            if rc is not None:
                err = read_json(self.last_error_file) or {}
                raise NorainError(
                    f"启动失败：{err.get('message', f'守护进程退出，退出码 {rc}')}",
                    exit_code=rc if 0 < rc < 10 else EXIT_EXTERNAL,
                    business_code=err.get("business_code", BIZ_PROCESS_EXITED), module="daemon",
                    hint="查看日志了解详情")
            info = read_json(self.runner_file) or {}
            if (_same_or_child(info.get("pid"), proc.pid) and info.get("ready")
                    and alive(info.get("child_pid"))):
                return
            time.sleep(0.1)
        raise NorainError("启动超时：sing-box 在限定时间内没有开始监听端口", exit_code=EXIT_TIMEOUT,
                          module="daemon", retryable=True, hint="查看日志了解详情")

    def stop(self, *, timeout: float = 20.0) -> None:
        info = runner_info(self.runner_file)
        if not info:
            return  # 幂等
        pid = info["pid"]
        try:
            cmd = " ".join(psutil.Process(pid).cmdline())
        except psutil.Error:
            return
        if "norain" not in cmd:
            raise NorainError(f"PID {pid} 不是 Norain 守护进程，拒绝停止", exit_code=EXIT_EXTERNAL,
                              module="daemon", hint=f"检查并删除过期的 {self.runner_file}")
        # 停止请求文件在所有平台都有效；POSIX 上再发 SIGTERM 让它立刻响应
        try:
            self.stop_file.parent.mkdir(parents=True, exist_ok=True)
            self.stop_file.write_text(str(os.getpid()))
        except OSError:
            pass
        if os.name == "posix":
            try:
                os.kill(pid, signal.SIGTERM)
            except PermissionError:
                raise NorainError(f"没有权限停止 PID {pid}", exit_code=EXIT_PERMISSION,
                                  module="daemon") from None
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not alive(pid):
                break
            time.sleep(0.1)
        else:
            _kill(pid)
            _kill(info.get("child_pid"))
        self.runner_file.unlink(missing_ok=True)
        self.stop_file.unlink(missing_ok=True)
