"""启动模块：开机自启动的注册，以及启动时的「测试检测模式」前半段。

启动顺序（最初目标）：
  1. 检查阻断模块的状态，如果处于阻断模式，先恢复为非阻断模式（pre_start）；
  2. 依次拉起分流模块、代理模块、监控模块；
  3. 监控通过后激活互拉保活，启动自维持模块。
第 2、3 步在内控制模块里执行（control.Controller.run），因为它们需要内控制审批。

正常模式 / 安全模式：app.mode = "normal" 且 app.auto_start = true 时注册开机自启动；
"safe" 时不自启动，只能用 `norain start` 手动启动。

自启动的实现：
  Windows  登录时运行的计划任务（TUN 和防火墙需要管理员权限，所以用最高权限运行）
  Linux    systemd 单元：root 安装时是系统单元，否则是用户单元
手动 stop 之后期望状态是 stopped，自启动入口检查到它就直接退出（docs/decisions/0013）。
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from norain_core import osutil
from norain_core.errors import EXIT_EXTERNAL, NorainError
from norain_core.log import Logger

from . import block
from .model import ClientConfig
from .paths import Paths

TASK_NAME = "Norain"
UNIT = "norain.service"

_UNIT_TEMPLATE = """\
# 由 norain 生成（启动模块）。手动 stop 之后期望状态为 stopped，`run --autostart` 会直接退出。
[Unit]
Description=Norain client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
{env}ExecStart={python} -m norain run --autostart
Restart=on-failure
RestartSec=5
# 3=配置无效 5=缺少 sing-box 9=已进入阻断或达到重启上限：再拉起也没用
RestartPreventExitStatus=3 5 9
KillMode=mixed
TimeoutStopSec=30

[Install]
WantedBy={target}
"""


def _env(paths: Paths) -> dict[str, str]:
    return {"NORAIN_HOME": str(paths.home), "NORAIN_CONFIG": str(paths.config),
            "NORAIN_STATE": str(paths.state)}


def _unit_path(system: bool) -> Path:
    if system:
        return Path("/etc/systemd/system") / UNIT
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd" / "user" / UNIT


def _systemctl(system: bool, *args: str):
    return osutil.run(["systemctl", *([] if system else ["--user"]), *args], timeout=30)


def register(paths: Paths, cfg: ClientConfig) -> str:
    """注册开机自启动（幂等）。返回说明文字。"""
    if osutil.IS_WINDOWS:
        admin = osutil.is_admin()
        if cfg.proxy.traffic_mode == "tun" and not admin:
            raise NorainError("TUN 模式的开机自启动需要以管理员身份注册", exit_code=4, module="boot",
                              hint="在管理员终端里重新运行这条命令")
        cmd = osutil.quote_cmd([osutil.python_exe(windowless=True), "-m", "norain", "boot", "--autostart"])
        osutil.task_create(TASK_NAME, cmd, trigger="ONLOGON", highest=admin)
        return f"计划任务 {TASK_NAME}（登录时运行{'，最高权限' if admin else ''}）"
    if not shutil.which("systemctl"):
        raise NorainError("没有 systemd，无法注册开机自启动", exit_code=EXIT_EXTERNAL, module="boot",
                          hint="可以把 `norain boot --autostart` 加到你的桌面环境的自启动项里")
    system = osutil.is_admin()
    unit = _unit_path(system)
    unit.parent.mkdir(parents=True, exist_ok=True)
    env = "".join(f'Environment="{k}={v}"\n' for k, v in _env(paths).items())
    unit.write_text(_UNIT_TEMPLATE.format(env=env, python=sys.executable,
                                          target="multi-user.target" if system else "default.target"),
                    encoding="utf-8")
    _systemctl(system, "daemon-reload")
    proc = _systemctl(system, "enable", UNIT)
    if proc.returncode != 0:
        raise NorainError(f"启用自启动失败：{(proc.stderr or proc.stdout).strip()[:300]}",
                          exit_code=EXIT_EXTERNAL, module="boot")
    return f"systemd {'系统' if system else '用户'}单元 {unit}"


def unregister() -> list[str]:
    done: list[str] = []
    if osutil.IS_WINDOWS:
        if osutil.task_delete(TASK_NAME):
            done.append(f"删除计划任务 {TASK_NAME}")
        return done
    for system in (True, False):
        unit = _unit_path(system)
        if unit.exists():
            _systemctl(system, "disable", UNIT)
            try:
                unit.unlink()
                done.append(f"删除 {unit}")
            except PermissionError:
                raise NorainError(f"没有权限删除 {unit}", exit_code=4, module="boot",
                                  hint="用 root 重新运行") from None
            _systemctl(system, "daemon-reload")
    return done


def registered() -> bool:
    if osutil.IS_WINDOWS:
        return osutil.task_exists(TASK_NAME)
    return _unit_path(True).exists() or _unit_path(False).exists()


def sync(paths: Paths, cfg: ClientConfig) -> str:
    """让自启动项与配置（正常模式 / 安全模式）一致。"""
    if cfg.autostart_wanted:
        return "已注册开机自启动：" + register(paths, cfg)
    removed = unregister()
    return "安全模式或已关闭自启动：" + ("；".join(removed) if removed else "没有自启动项")


def pre_start(paths: Paths, log: Logger | None = None) -> dict:
    """测试检测模式的第一步：处于阻断模式时自动恢复为非阻断模式。"""
    if not block.is_active(paths) and not (paths.block_state.exists()):
        return {"was_blocked": False}
    res = block.release(paths, log=log)
    if log:
        log.info("boot.block_released", was_active=res["was_active"])
    return {"was_blocked": res["was_active"]}
