"""Windows 系统代理（WinINET）的注册表快照与还原。

sing-box 的 inbound 支持 `set_system_proxy`，但它自己管不好这件事（2026-11-15 用
sing-box 1.14.4 实测）：

* 运行期写 `ProxyEnable=1`、`ProxyServer="http://127.0.0.1:<port>"`；
* 被**硬终止**（Windows 上是 TerminateProcess，norain 停子进程就用 `terminate()`）时
  什么都不还原——系统代理留在死端口，整机浏览器随即断网；
* 正常退出（Ctrl+Break）也只把 `ProxyEnable` 置 0，**不回填原来的 `ProxyServer`**。

所以客户端在启动 sing-box 之前自己快照注册表，停止之后再原样写回。快照落盘
（`paths.sysproxy_state`），进程被强杀后下次启动会先还原它，避免残留。

测试里 `NORAIN_NO_SYSTEM_CHANGES=1` 会让 `supported()` 返回 False，本模块整体变成空操作；
需要断言逻辑的用例用 monkeypatch 替换 `read`/`write`/`notify`。
"""

from __future__ import annotations

import json
from pathlib import Path

from . import osutil

KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
FIELDS = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")
# INTERNET_OPTION_SETTINGS_CHANGED = 39, INTERNET_OPTION_REFRESH = 37
_REFRESH_OPTIONS = (39, 37)


def supported() -> bool:
    """只有 Windows 且允许改系统设置时才生效。"""
    return osutil.IS_WINDOWS and not osutil.system_changes_disabled()


def read() -> dict | None:
    """当前注册表值。缺失的值记为 None；不在 Windows 或禁止改动时返回 None。"""
    if not supported():
        return None
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY) as k:
            values: dict = {}
            for name in FIELDS:
                try:
                    values[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    values[name] = None
            return values
    except OSError:
        return None


def notify() -> None:
    """告诉正在运行的程序重新读取代理设置。失败不影响主流程。"""
    if not osutil.IS_WINDOWS or osutil.system_changes_disabled():
        return
    try:
        import ctypes

        wininet = ctypes.windll.wininet
        for option in _REFRESH_OPTIONS:
            wininet.InternetSetOptionW(0, option, 0, 0)
    except Exception:  # noqa: BLE001 通知失败不能让停止流程失败
        pass


def write(values: dict) -> bool:
    """把快照写回注册表。值为 None 的项删除（例如原本没有 AutoConfigURL）。"""
    if not supported():
        return False
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as k:
        for name in FIELDS:
            if name not in values:
                continue
            value = values[name]
            if value is None:
                try:
                    winreg.DeleteValue(k, name)
                except OSError:
                    pass
            elif name == "ProxyEnable":
                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))
            else:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(value))
    notify()
    return True


def save(path: Path, values: dict) -> None:
    from .state import write_json

    write_json(path, {"saved_at": __import__("time").time(), "values": values})


def load(path: Path) -> dict | None:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    values = obj.get("values") if isinstance(obj, dict) else None
    return values if isinstance(values, dict) else None


def discard(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
