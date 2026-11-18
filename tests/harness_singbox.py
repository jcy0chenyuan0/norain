"""行为测试共用的等待与进程工具。

两个要点：
  - 用「端口可连」代替固定 sleep：sing-box 通常 0.3s 内就绪，盲等 2s 纯浪费。
  - 把「启动→等待→测试→结束」拆开，让一个模块能共用一个 sing-box 进程。
"""

import contextlib
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

READY_TIMEOUT = 10.0   # 超过这个时间还起不来就算失败，避免测试无限挂住
READY_INTERVAL = 0.02


def wait_port(port: int, *, host: str = "127.0.0.1", timeout: float = READY_TIMEOUT) -> bool:
    """等到端口能建立连接为止。返回是否成功。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(READY_INTERVAL)
    return False


def wait_for(predicate, *, timeout: float = 3.0, interval: float = 0.02) -> bool:
    """等到 predicate() 为真。返回是否在超时前满足。

    用于「等某个事件发生」；比固定 sleep 快，也比固定 sleep 稳。
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class RunningSingBox:
    """启动一个 sing-box，提供就绪等待、日志收集与停止。"""

    def __init__(self, binary: str, config: Path, *, ready_ports: tuple[int, ...] = ()):
        self.binary = binary
        self.config = config
        self.ready_ports = ready_ports
        self.proc: subprocess.Popen | None = None
        self.logs: list[str] = []
        self._reader: threading.Thread | None = None

    def start(self) -> "RunningSingBox":
        self.proc = subprocess.Popen([self.binary, "run", "-c", str(self.config)],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, errors="replace")
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        for port in self.ready_ports:
            if not wait_port(port):
                tail = "".join(self.logs[-20:])
                self.stop()
                raise RuntimeError(f"sing-box 没有在超时内监听 {port}\n--- 最近的日志 ---\n{tail}")
        return self

    def _pump(self):
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            self.logs.append(line)

    def stop(self):
        """先 terminate，超时再 kill；两种情况都等到进程真的退出，避免留下僵尸。"""
        if not self.proc:
            return
        proc = self.proc
        self.proc = None
        try:
            proc.terminate()
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            # kill 之后必须再 wait，否则 Windows 上句柄和进程都可能残留
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(5)
        finally:
            if proc.stdout is not None:
                with contextlib.suppress(OSError, ValueError):
                    proc.stdout.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def check_config(binary: str, config: Path) -> None:
    """跑 sing-box check，失败时把完整输出抛出来便于诊断。"""
    r = subprocess.run([binary, "check", "-c", str(config)], capture_output=True,
                       text=True, errors="replace", timeout=60)
    if r.returncode != 0:
        raise AssertionError(f"sing-box check 失败:\n{r.stdout}\n{r.stderr}")


def find_singbox() -> str | None:
    """找真实 sing-box：NORAIN_TEST_SINGBOX > 已安装的 norain 二进制 > 常见路径。"""
    env = os.environ.get("NORAIN_TEST_SINGBOX")
    if env and Path(env).is_file():
        return env
    home = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    for cand in (home / "norain" / "bin" / "sing-box.exe",
                 home / "norain" / "bin" / "sing-box",
                 Path("/usr/local/bin/sing-box"),
                 Path("/usr/bin/sing-box")):
        if cand.is_file():
            return str(cand)
    return None
