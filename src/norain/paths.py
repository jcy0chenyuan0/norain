"""客户端路径。客户端是用户级程序，不需要管理员权限。

| | Windows | Linux |
|---|---|---|
| 配置 | %APPDATA%\\norain\\cfg.toml | ~/.config/norain/cfg.toml |
| 状态 | %LOCALAPPDATA%\\norain | ~/.local/state/norain |
| 日志 | %LOCALAPPDATA%\\norain\\log | ~/.local/state/norain/log |

环境变量 NORAIN_HOME、NORAIN_CONFIG、NORAIN_STATE、NORAIN_LOG、NORAIN_SINGBOX 优先。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _defaults(env, platform: str) -> tuple[Path, Path]:
    home = Path(env.get("USERPROFILE") or env.get("HOME") or Path.home())
    if platform == "nt":
        roaming = Path(env.get("APPDATA") or home / "AppData" / "Roaming")
        local = Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local")
        return roaming / "norain", local / "norain"
    config = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    state = Path(env.get("XDG_STATE_HOME") or home / ".local" / "state")
    return config / "norain", state / "norain"


@dataclass(frozen=True)
class Paths:
    home: Path
    config: Path
    state: Path
    log_dir: Path
    log_dir_from_env: bool
    singbox: str | None
    platform: str

    @classmethod
    def from_env(cls, env=None, platform: str | None = None) -> "Paths":
        env = os.environ if env is None else env
        platform = platform or os.name
        d_home, d_state = _defaults(env, platform)
        home = Path(env.get("NORAIN_HOME") or d_home)
        state = Path(env.get("NORAIN_STATE") or d_state)
        return cls(
            home=home,
            config=Path(env.get("NORAIN_CONFIG") or home / "cfg.toml"),
            state=state,
            log_dir=Path(env.get("NORAIN_LOG") or state / "log"),
            log_dir_from_env=bool(env.get("NORAIN_LOG")),
            singbox=env.get("NORAIN_SINGBOX") or None,
            platform=platform,
        )

    def with_log_dir(self, directory: str) -> "Paths":
        if directory and not self.log_dir_from_env:
            return Paths(self.home, self.config, self.state, Path(directory).expanduser(), False,
                         self.singbox, self.platform)
        return self

    @property
    def bundled_singbox(self) -> Path:
        return self.state / "bin" / ("sing-box.exe" if self.platform == "nt" else "sing-box")

    @property
    def run_dir(self) -> Path: return self.state / "run"
    @property
    def current_json(self) -> Path: return self.run_dir / "sing-box.json"
    @property
    def meta_json(self) -> Path: return self.run_dir / "sing-box.json.meta.json"
    @property
    def backups(self) -> Path: return self.state / "backups"
    @property
    def desired(self) -> Path: return self.state / "desired-state.json"
    @property
    def lock(self) -> Path: return self.state / "op.lock"
    @property
    def runner(self) -> Path: return self.run_dir / "runner.json"
    @property
    def stop_file(self) -> Path: return self.run_dir / "stop-request"
    @property
    def last_error(self) -> Path: return self.state / "last-error.json"
    @property
    def log_file(self) -> Path: return self.log_dir / "norain.log"

    # ---- 各模块的状态文件 ----
    @property
    def bin_dir(self) -> Path: return self.state / "bin"
    @property
    def cache_dir(self) -> Path: return self.state / "cache"
    @property
    def status_file(self) -> Path: return self.run_dir / "status.json"        # 内控制写，CLI 读
    @property
    def ctl_dir(self) -> Path: return self.run_dir / "ctl"                    # CLI → 内控制的请求
    @property
    def proxy_state(self) -> Path: return self.run_dir / "proxy.json"         # 代理模块（sing-box）
    @property
    def proxy_stop(self) -> Path: return self.run_dir / "proxy-stop"
    @property
    def watchdog_file(self) -> Path: return self.run_dir / "watchdog.json"    # 看门狗进程
    @property
    def block_state(self) -> Path: return self.state / "isolation.json"       # 阻断模式
    @property
    def rules_dir(self) -> Path: return self.state / "rules"
    @property
    def routing_dir(self) -> Path: return self.state / "routing"
    @property
    def learned(self) -> Path: return self.routing_dir / "learned.json"       # 自动学到的名单
    @property
    def selection(self) -> Path: return self.state / "selection.json"         # 自适应选中的协议
    @property
    def package_dir(self) -> Path: return self.state / "package"              # 安装包副本（修复用）
    @property
    def manifest(self) -> Path: return self.package_dir / "manifest.json"
    @property
    def package_zip(self) -> Path: return self.package_dir / "norain-pkg.zip"
    @property
    def orig_config(self) -> Path: return self.package_dir / "cfg.toml.orig"  # 安装时的初始配置
    @property
    def install_record(self) -> Path: return self.state / "install.json"
