"""服务端的两种后端。

- SystemdBackend：已安装 norain-server.service 时使用（见 deploy/）。
- DetachedBackend：没有 systemd 单元时，直接在后台启动 `norain-server run`。
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Callable

from norain_core import osutil
from norain_core.daemonctl import DetachedBackend, ServiceStatus, runner_info
from norain_core.errors import EXIT_EXTERNAL, EXIT_PERMISSION, NorainError
from norain_core.redact import redact

from .paths import Paths

UNIT = "norain-server.service"
Run = Callable[[list[str]], subprocess.CompletedProcess]


def _default_run(args: list[str]) -> subprocess.CompletedProcess:
    return osutil.run(args)   # 隐藏控制台窗口；命令不存在或超时时返回非零退出码而不是抛异常


def detached(paths: Paths) -> DetachedBackend:
    return DetachedBackend(module="norain_server", runner_file=paths.runner,
                           last_error_file=paths.last_error, stop_file=paths.stop_file,
                           log_dir=paths.log_dir)


class SystemdBackend:
    name = "systemd"

    def __init__(self, paths: Paths, run: Run = _default_run) -> None:
        self.paths, self._run = paths, run

    @staticmethod
    def available(run: Run = _default_run) -> bool:
        if not shutil.which("systemctl"):
            return False
        try:
            proc = run(["systemctl", "list-unit-files", UNIT, "--no-legend"])
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0 and UNIT in proc.stdout

    def _ctl(self, *args: str) -> None:
        proc = self._run(["systemctl", *args, UNIT])
        if proc.returncode != 0:
            msg = redact(proc.stderr.strip() or proc.stdout.strip())
            denied = "ccess denied" in msg or "authentication" in msg.lower()
            raise NorainError(f"systemctl {' '.join(args)} 失败：{msg}",
                              exit_code=EXIT_PERMISSION if denied else EXIT_EXTERNAL,
                              module="daemon", hint="用 root 或 sudo 运行" if denied else "")

    def start(self, *, timeout: float = 20.0) -> None:
        self._run(["systemctl", "reset-failed", UNIT])
        self._ctl("start")

    def stop(self, *, timeout: float = 20.0) -> None:
        self._ctl("stop")

    def status(self) -> ServiceStatus:
        proc = self._run(["systemctl", "show", UNIT, "-p", "ActiveState,MainPID,NRestarts"])
        props = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
        active = props.get("ActiveState", "inactive")
        state = {"active": "running", "activating": "running", "failed": "failed"}.get(active, "stopped")
        info = runner_info(self.paths.runner)
        return ServiceStatus(self.name, state, int(props.get("MainPID") or 0) or None,
                             info.get("child_pid"), info.get("restarts", 0),
                             int(props.get("NRestarts") or 0))


def pick_backend(paths: Paths):
    if os.environ.get("NORAIN_SERVER_BACKEND") == "detached" or os.name == "nt":
        return detached(paths)  # Windows：开机计划任务只负责拉起 `run --if-desired`
    if SystemdBackend.available():
        return SystemdBackend(paths)
    return detached(paths)
