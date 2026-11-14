"""系统适配：管理员判断、外部命令、后台进程、持久环境变量、PATH、启动器、弹窗、计划任务。

Windows 与 Linux 的差异都收在这里，上层模块不直接拼系统命令。
本模块里的系统命令均按官方文档书写，尚未在真实系统上验证。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .errors import EXIT_EXTERNAL, EXIT_PERMISSION, NorainError
from .redact import redact

IS_WINDOWS = os.name == "nt"


# ---- 权限与命令 ----------------------------------------------------------------

def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return os.geteuid() == 0


def require_admin(what: str, *, module: str = "core") -> None:
    if not is_admin():
        raise NorainError(f"{what}需要管理员权限", exit_code=EXIT_PERMISSION, module=module,
                          hint="Windows 用「以管理员身份运行」的终端；Linux 用 root 或 sudo")


def run(args: list[str], *, timeout: float = 60, input_text: str | None = None) -> subprocess.CompletedProcess:
    """执行外部命令并捕获输出。命令不存在时返回 returncode=127，而不是抛异常。"""
    extra = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}
    try:
        return subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=timeout,
                              input=input_text, **extra)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, "", f"找不到命令：{args[0]}")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", f"命令超时（{timeout:.0f} 秒）：{args[0]}")
    except OSError as e:
        return subprocess.CompletedProcess(args, 126, "", f"无法执行 {args[0]}：{e}")


def run_checked(args: list[str], *, what: str, module: str = "core", timeout: float = 60) -> str:
    """执行失败时抛出带具体原因的错误（不静默忽略）。"""
    proc = run(args, timeout=timeout)
    if proc.returncode != 0:
        detail = redact((proc.stderr or proc.stdout or "").strip())[-800:]
        low = detail.lower()
        denied = "denied" in low or "拒绝访问" in detail or "permission" in low or "需要提升" in detail
        raise NorainError(f"{what}失败（{' '.join(args[:3])} 退出码 {proc.returncode}）：{detail}",
                          exit_code=EXIT_PERMISSION if denied else EXIT_EXTERNAL, module=module,
                          hint="用管理员/root 权限重试" if denied else "")
    return proc.stdout


def powershell(script: str, *, timeout: float = 60) -> subprocess.CompletedProcess:
    return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-Command", script], timeout=timeout)


def python_exe(*, windowless: bool = False) -> str:
    """当前解释器。windowless=True 时在 Windows 上优先用 pythonw.exe（不弹控制台窗口）。"""
    exe = Path(sys.executable)
    if windowless and IS_WINDOWS:
        w = exe.with_name("pythonw.exe")
        if w.is_file():
            return str(w)
    return str(exe)


def spawn_detached(args: list[str], *, log_file: Path | None = None, env: dict | None = None) -> subprocess.Popen:
    """启动一个脱离当前终端和进程组的后台进程。"""
    extra: dict = {}
    if IS_WINDOWS:
        extra["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                                  | subprocess.CREATE_NO_WINDOW)
    else:
        extra["start_new_session"] = True
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "ab") as out:
            return subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=out,
                                    close_fds=True, env=env, **extra)
    return subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, close_fds=True, env=env, **extra)


# ---- 持久环境变量与 PATH ------------------------------------------------------

_WIN_ENV_USER = r"Environment"
_WIN_ENV_SYSTEM = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"


def _win_broadcast_env() -> None:
    try:
        import ctypes
        ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002, 3000, None)
    except Exception:  # noqa: BLE001 通知失败只影响已打开的窗口，新终端仍会读到
        pass


def _win_env_key(system: bool, write: bool):
    import winreg
    root = winreg.HKEY_LOCAL_MACHINE if system else winreg.HKEY_CURRENT_USER
    access = winreg.KEY_READ | (winreg.KEY_SET_VALUE if write else 0)
    return winreg.OpenKey(root, _WIN_ENV_SYSTEM if system else _WIN_ENV_USER, 0, access)


def _profile_file(name: str, system: bool) -> Path:
    if system:
        return Path("/etc/profile.d") / f"{name}.sh"
    return Path.home() / ".config" / name / "env.sh"


_PROFILE_HOOK = "# norain-env:{name}\n[ -f \"{path}\" ] && . \"{path}\"\n"


def persist_env(variables: dict[str, str], *, system: bool, name: str,
                path_dirs: tuple[str, ...] = ()) -> list[str]:
    """持久写入环境变量，并把 path_dirs 加入 PATH。返回做了什么的说明。

    Windows：setx（系统级加 /M）；PATH 直接改注册表，避免 setx 的 1024 字符截断。
    Linux：系统级写 /etc/profile.d/<name>.sh；用户级写 ~/.config/<name>/env.sh 并在 ~/.profile 里引用。
    """
    done: list[str] = []
    if IS_WINDOWS:
        for k, v in variables.items():
            run_checked(["setx", k, v, *(["/M"] if system else [])], what=f"写入环境变量 {k}")
            done.append(f"setx {k}")
        if path_dirs:
            import winreg
            with _win_env_key(system, True) as key:
                try:
                    current, kind = winreg.QueryValueEx(key, "Path")
                except FileNotFoundError:
                    current, kind = "", winreg.REG_EXPAND_SZ
                parts = [p for p in current.split(";") if p]
                lowered = {p.lower().rstrip("\\") for p in parts}
                for d in path_dirs:
                    if d.lower().rstrip("\\") not in lowered:
                        parts.append(d)
                        done.append(f"PATH += {d}")
                winreg.SetValueEx(key, "Path", 0, kind, ";".join(parts))
            _win_broadcast_env()
        return done
    lines = [f"# 由 {name} 生成，卸载时删除"]
    lines += [f"export {k}='{v}'" for k, v in variables.items()]
    for d in path_dirs:
        lines.append(f'case ":$PATH:" in *":{d}:"*) ;; *) export PATH="$PATH:{d}" ;; esac')
    f = _profile_file(name, system)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(f, 0o644)
    done.append(f"写入 {f}")
    if not system:
        profile = Path.home() / ".profile"
        hook = _PROFILE_HOOK.format(name=name, path=f)
        text = profile.read_text(encoding="utf-8") if profile.exists() else ""
        if f"# norain-env:{name}" not in text:
            profile.write_text(text + ("" if text.endswith("\n") or not text else "\n") + hook,
                               encoding="utf-8")
            done.append(f"在 {profile} 中引用")
    return done


def unpersist_env(names: list[str], *, system: bool, name: str, path_dirs: tuple[str, ...] = ()) -> list[str]:
    done: list[str] = []
    if IS_WINDOWS:
        import winreg
        try:
            with _win_env_key(system, True) as key:
                for k in names:
                    try:
                        winreg.DeleteValue(key, k)
                        done.append(f"删除环境变量 {k}")
                    except FileNotFoundError:
                        pass
                if path_dirs:
                    try:
                        current, kind = winreg.QueryValueEx(key, "Path")
                        drop = {d.lower().rstrip("\\") for d in path_dirs}
                        parts = [p for p in current.split(";") if p and p.lower().rstrip("\\") not in drop]
                        winreg.SetValueEx(key, "Path", 0, kind, ";".join(parts))
                        done.append("从 PATH 移除 Norain 目录")
                    except FileNotFoundError:
                        pass
        except PermissionError:
            raise NorainError("没有权限修改环境变量", exit_code=EXIT_PERMISSION, module="core") from None
        _win_broadcast_env()
        return done
    f = _profile_file(name, system)
    if f.exists():
        f.unlink()
        done.append(f"删除 {f}")
    if not system:
        profile = Path.home() / ".profile"
        if profile.exists():
            lines = profile.read_text(encoding="utf-8").splitlines(keepends=True)
            out, skip = [], 0
            for line in lines:
                if line.startswith(f"# norain-env:{name}"):
                    skip = 1  # 连同下一行（引用行）一起删除
                    continue
                if skip:
                    skip = 0
                    continue
                out.append(line)
            if len(out) != len(lines):
                profile.write_text("".join(out), encoding="utf-8")
                done.append(f"清理 {profile}")
    return done


# ---- 启动器 --------------------------------------------------------------------

_MARK = "norain-launcher"


def write_launcher(directory: Path, name: str, module: str) -> Path:
    """生成 `<name>` 命令的启动器，调用 `<当前解释器> -m <module>`。"""
    directory.mkdir(parents=True, exist_ok=True)
    if IS_WINDOWS:
        path = directory / f"{name}.cmd"
        path.write_text(f'@echo off\r\nrem {_MARK}\r\n"{sys.executable}" -m {module} %*\r\n', encoding="utf-8")
    else:
        path = directory / name
        path.write_text(f'#!/bin/sh\n# {_MARK}\nexec "{sys.executable}" -m {module} "$@"\n', encoding="utf-8")
        os.chmod(path, 0o755)
    return path


def remove_launcher(directory: Path, name: str) -> bool:
    """只删除本程序生成的启动器，不动 pip 等其他来源安装的同名命令。"""
    path = directory / (f"{name}.cmd" if IS_WINDOWS else name)
    try:
        if path.is_file() and _MARK in path.read_text(encoding="utf-8", errors="replace"):
            path.unlink()
            return True
    except OSError:
        pass
    return False


# ---- 弹窗 ----------------------------------------------------------------------

def popup(title: str, text: str) -> bool:
    """给用户一个不阻塞调用方的提醒窗口。没有图形界面时返回 False（调用方另行写日志）。"""
    if IS_WINDOWS:
        # MessageBoxW 会阻塞到用户点击，所以放到独立进程里
        code = ("import ctypes,sys;"
                "ctypes.windll.user32.MessageBoxW(0, sys.argv[2], sys.argv[1], 0x30 | 0x1000 | 0x40000)")
        try:
            spawn_detached([python_exe(windowless=True), "-c", code, title, text])
            return True
        except OSError:
            return False
    for cmd in (["zenity", "--warning", "--no-wrap", f"--title={title}", f"--text={text}"],
                ["kdialog", "--title", title, "--sorry", text],
                ["notify-send", "-u", "critical", title, text]):
        if shutil.which(cmd[0]) and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            try:
                spawn_detached(cmd)
                return True
            except OSError:
                continue
    if shutil.which("wall"):
        run(["wall", f"{title}\n{text}"], timeout=5)
        return True
    return False


# ---- Windows 计划任务 ----------------------------------------------------------

def task_create(name: str, command: str, *, trigger: str, highest: bool, as_system: bool = False) -> None:
    """trigger: ONLOGON（用户登录时）或 ONSTART（开机时）。已存在则覆盖（幂等）。"""
    args = ["schtasks", "/Create", "/TN", name, "/TR", command, "/SC", trigger, "/F"]
    if highest:
        args += ["/RL", "HIGHEST"]
    if as_system:
        args += ["/RU", "SYSTEM"]
    run_checked(args, what=f"注册计划任务 {name}")


def task_delete(name: str) -> bool:
    if not task_exists(name):
        return False
    run_checked(["schtasks", "/Delete", "/TN", name, "/F"], what=f"删除计划任务 {name}")
    return True


def task_exists(name: str) -> bool:
    return run(["schtasks", "/Query", "/TN", name], timeout=20).returncode == 0


def quote_cmd(args: list[str]) -> str:
    return subprocess.list2cmdline(args)
