"""通过独立的 Windows 控制台让子进程有机会正常退出。"""

import os
import subprocess
import sys
from pathlib import Path


def hidden_console_options() -> dict:
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    return {"creationflags": subprocess.CREATE_NEW_CONSOLE, "startupinfo": startup}


def request_interrupt(pid: int) -> bool:
    # 另起进程附加控制台，避免更改 Norain 守护进程自己的控制台和信号处理器。
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(Path(__file__).resolve()), str(pid)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.DETACHED_PROCESS, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _send_control_c(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32")
    if not kernel.AttachConsole(wintypes.DWORD(pid)):
        return False
    try:
        # Ctrl+C 会广播给同一控制台。确认只有目标子进程和这个发送进程在内。
        processes = (wintypes.DWORD * 2)()
        if kernel.GetConsoleProcessList(processes, len(processes)) != 2:
            return False
        if set(processes) != {pid, os.getpid()}:
            return False
        return bool(kernel.SetConsoleCtrlHandler(None, True)
                    and kernel.GenerateConsoleCtrlEvent(0, 0))
    finally:
        kernel.FreeConsole()


if __name__ == "__main__":
    raise SystemExit(0 if _send_control_c(int(sys.argv[1])) else 1)
