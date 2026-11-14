"""sing-box 子进程监督器，客户端和服务端共用。

- 启动 sing-box，定时检查进程、端口监听和 fatal 日志；
- 异常时重启，连续重启超过上限后以 EXIT_RESTART_LIMIT 退出；
- 停止请求有两种来源：停止请求文件（跨平台）和 SIGTERM/SIGINT（POSIX）。
  Windows 上向进程发信号等于强制结束，所以必须用停止请求文件才能干净退出。
- 重载请求（重载请求文件或 request_reload()）：重启子进程以加载新配置，不计入失败次数。
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import psutil

from .errors import (BIZ_PORT_IN_USE, BIZ_PROCESS_EXITED, BIZ_RESTART_LIMIT, EXIT_EXTERNAL,
                     EXIT_OK, EXIT_PERMISSION, EXIT_RESTART_LIMIT, NorainError)
from .log import Logger, RotatingFile
from .redact import redact
from .state import write_json

_FATAL = re.compile(r"\bFATAL\b|\bpanic:", re.I)
STOP_GRACE_SECONDS = 10

RELOAD = "<reload>"  # _supervise 的返回值：按请求重启子进程，不算故障

Listener = tuple[str, str, int]  # (监听地址, "tcp" | "udp", 端口)


@dataclass
class Spec:
    binary: Path
    config_json: Path
    config_version: str
    listeners: list[Listener]
    check_interval: float
    restart_limit: int
    backoff: float
    log_file: Path
    log_max_bytes: int
    log_keep: int
    log_level: str
    runner_file: Path
    last_error_file: Path
    stop_file: Path
    reload_file: Path | None = None                 # 出现该文件时重启子进程（不计失败）
    on_line: Callable[[str], None] | None = None    # 每行（已脱敏的）sing-box 输出的回调


def check_ports_free(listeners: list[Listener]) -> None:
    for listen, proto, port in listeners:
        family = socket.AF_INET6 if ":" in listen else socket.AF_INET
        kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
        with socket.socket(family, kind) as s:
            if proto == "tcp" and os.name == "posix":
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((listen, port))
            except OSError as e:
                in_use = e.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1))
                denied = e.errno in (errno.EACCES, getattr(errno, "WSAEACCES", -1))
                if in_use:
                    msg, hint = f"端口 {port}/{proto} 已被占用", "换一个端口，或关闭占用它的程序"
                elif denied:
                    msg, hint = f"没有权限监听 {port}/{proto}", "用更高的端口，或以管理员/root 运行"
                else:
                    msg, hint = f"无法监听 {listen}:{port}/{proto}：{e}", ""
                raise NorainError(msg, exit_code=EXIT_PERMISSION if denied else EXIT_EXTERNAL,
                                  business_code=BIZ_PORT_IN_USE, module="daemon", hint=hint) from None


def missing_listeners(pid: int, listeners: list[Listener]) -> list[str] | None:
    """返回没有在监听的端口；无法检查时返回 None。"""
    try:
        proc = psutil.Process(pid)
        conns = []
        for p in (proc, *proc.children(recursive=True)):
            fn = getattr(p, "net_connections", None) or p.connections
            conns += fn(kind="inet")
    except (psutil.Error, OSError):
        return None
    have = {("udp" if c.type == socket.SOCK_DGRAM else "tcp", c.laddr.port)
            for c in conns if c.laddr and (c.type == socket.SOCK_DGRAM or c.status == psutil.CONN_LISTEN)}
    return [f"{port}/{proto}" for _, proto, port in listeners if (proto, port) not in have]


def record_error(path: Path, business_code: int, message: str) -> None:
    try:
        write_json(path, {"business_code": business_code, "message": redact(message),
                          "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
    except OSError:
        pass


class Supervisor:
    def __init__(self, spec: Spec) -> None:
        self.spec = spec
        self._stop = threading.Event()
        self._reload = threading.Event()
        self._child: subprocess.Popen | None = None
        self._fatal: str | None = None
        self.total_restarts = 0

    def request_stop(self, *_args) -> None:
        self._stop.set()

    def request_reload(self) -> None:
        self._reload.set()

    @property
    def child_pid(self) -> int | None:
        child = self._child
        return child.pid if child is not None and child.poll() is None else None

    def _reload_requested(self) -> bool:
        rf = self.spec.reload_file
        hit = self._reload.is_set()
        if rf is not None and rf.exists():
            rf.unlink(missing_ok=True)
            hit = True
        self._reload.clear()
        return hit

    def _stop_requested(self, wait: float) -> bool:
        if self._stop.wait(wait):
            return True
        if self.spec.stop_file.exists():
            self._stop.set()
            return True
        return False

    def _pump(self, child: subprocess.Popen, sink: RotatingFile) -> None:
        assert child.stdout is not None
        for raw in child.stdout:
            line = redact(raw.rstrip("\n"))
            sink.write_line(line)
            if _FATAL.search(line):
                self._fatal = line[-500:]
            if self.spec.on_line is not None:
                try:
                    self.spec.on_line(line)
                except Exception:  # noqa: BLE001 回调出错不能中断日志泵
                    pass

    @staticmethod
    def _terminate(child: subprocess.Popen) -> None:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(STOP_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(5)

    def _write_runner(self, child_pid: int | None, consecutive: int, ready: bool = False) -> None:
        write_json(self.spec.runner_file, {
            "pid": os.getpid(), "child_pid": child_pid, "ready": ready,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "restarts": self.total_restarts, "consecutive_restarts": consecutive,
            "config_version": self._config_version(), "log_file": str(self.spec.log_file),
        })

    def _config_version(self) -> str:
        """重载后配置文件内容会变，版本号以磁盘上的当前配置为准。"""
        try:
            return hashlib.sha256(self.spec.config_json.read_bytes()).hexdigest()[:12]
        except OSError:
            return self.spec.config_version

    def _supervise(self, child: subprocess.Popen, log: Logger, consecutive: int) -> str | None:
        """阻塞到子进程需要处理为止。返回故障原因；用户要求停止时返回 None。"""
        spec = self.spec
        started = time.monotonic()
        next_check = started + spec.check_interval
        ready = False
        while True:
            if self._stop_requested(0.2):
                self._terminate(child)
                return None
            if self._reload_requested():
                self._terminate(child)
                return RELOAD
            rc = child.poll()
            if rc is not None:
                return f"sing-box 退出，退出码 {rc}"
            if not ready:
                # 就绪：端口都在监听；无法检查端口时，存活满 1 秒视为就绪
                missing = missing_listeners(child.pid, spec.listeners)
                if missing == [] or (missing is None and time.monotonic() - started >= 1):
                    ready = True
                    self._write_runner(child.pid, consecutive, ready=True)
                    log.info("singbox.ready", pid=child.pid)
            if time.monotonic() < next_check:
                continue
            next_check = time.monotonic() + spec.check_interval
            if self._fatal:
                reason = f"日志出现 fatal：{self._fatal}"
            else:
                missing = missing_listeners(child.pid, spec.listeners)
                if missing is None:
                    log.warn("health.ports_unknown")
                reason = f"端口没有在监听：{', '.join(missing)}" if missing else None
            if reason:
                self._terminate(child)
                return reason
            log.debug("health.ok")

    def run(self) -> int:
        spec = self.spec
        sink = RotatingFile(spec.log_file, max_bytes=spec.log_max_bytes, keep=spec.log_keep)
        log = Logger("daemon", sink=sink, level=spec.log_level)
        spec.stop_file.unlink(missing_ok=True)
        if spec.reload_file is not None:
            spec.reload_file.unlink(missing_ok=True)
        try:
            signal.signal(signal.SIGTERM, self.request_stop)
            signal.signal(signal.SIGINT, self.request_stop)
        except ValueError:
            pass  # 不在主线程（测试中）

        stable_after = max(2 * spec.check_interval, 60.0)
        consecutive = 0
        popen_extra = {}
        if os.name == "nt":
            popen_extra["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            while True:
                self._fatal = None
                child = subprocess.Popen(
                    [str(spec.binary), "run", "-c", str(spec.config_json)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace", **popen_extra)
                self._child = child
                started = time.monotonic()
                self._write_runner(child.pid, consecutive)
                log.info("singbox.started", pid=child.pid, config_version=self._config_version(),
                         restarts=self.total_restarts)
                pump = threading.Thread(target=self._pump, args=(child, sink), daemon=True)
                pump.start()

                reason = self._supervise(child, log, consecutive)
                pump.join(2)
                if reason is None:
                    log.info("daemon.stopped", reason="stop requested")
                    return EXIT_OK
                if reason == RELOAD:
                    log.info("singbox.reloading")
                    consecutive = 0
                    continue

                record_error(spec.last_error_file, BIZ_PROCESS_EXITED, reason)
                log.error("singbox.failed", reason=reason, business_code=BIZ_PROCESS_EXITED)
                if time.monotonic() - started >= stable_after:
                    consecutive = 0
                consecutive += 1
                if consecutive > spec.restart_limit:
                    msg = f"连续重启 {spec.restart_limit} 次后仍然失败，停止重启。最后原因：{reason}"
                    record_error(spec.last_error_file, BIZ_RESTART_LIMIT, msg)
                    log.error("daemon.restart_limit", limit=spec.restart_limit,
                              business_code=BIZ_RESTART_LIMIT)
                    return EXIT_RESTART_LIMIT
                self.total_restarts += 1
                delay = min(spec.backoff * 2 ** (consecutive - 1), 300)
                log.warn("singbox.restarting", attempt=consecutive, limit=spec.restart_limit,
                         delay_seconds=delay)
                if self._stop_requested(delay):
                    log.info("daemon.stopped", reason="stop requested during backoff")
                    return EXIT_OK
        finally:
            if self._child is not None:
                self._terminate(self._child)
            spec.runner_file.unlink(missing_ok=True)
            spec.stop_file.unlink(missing_ok=True)
