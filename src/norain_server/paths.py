"""服务端路径。启动时优先读环境变量，其次用默认路径（最初目标）。

| | Linux | Windows |
|---|---|---|
| 配置 | /etc/norain-server | %ProgramData%/norain-server |
| 状态 | /var/lib/norain-server | %ProgramData%/norain-server/state |
| 日志 | /var/log/norain-server | %ProgramData%/norain-server/log |
| sing-box | /usr/local/bin/sing-box | %ProgramFiles%/norain-server/sing-box.exe |
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    home: Path
    config: Path
    state: Path
    log_dir: Path
    log_dir_from_env: bool
    singbox: str | None
    platform: str = os.name

    @classmethod
    def from_env(cls, env=None, platform: str | None = None) -> "Paths":
        env = os.environ if env is None else env
        platform = platform or os.name
        if platform == "nt":
            data = Path(env.get("ProgramData") or env.get("PROGRAMDATA") or "C:/ProgramData") / "norain-server"
            d_home, d_state, d_log = data, data / "state", data / "log"
        else:
            d_home, d_state, d_log = (Path("/etc/norain-server"), Path("/var/lib/norain-server"),
                                      Path("/var/log/norain-server"))
        home = Path(env.get("NORAIN_SERVER_HOME") or d_home)
        return cls(
            home=home,
            config=Path(env.get("NORAIN_SERVER_CONFIG") or home / "server.toml"),
            state=Path(env.get("NORAIN_SERVER_STATE") or d_state),
            log_dir=Path(env.get("NORAIN_SERVER_LOG") or d_log),
            log_dir_from_env=bool(env.get("NORAIN_SERVER_LOG")),
            singbox=env.get("NORAIN_SERVER_SINGBOX") or None,
            platform=platform,
        )

    def with_log_dir(self, directory: str) -> "Paths":
        """server.toml 的 logging.directory 只在环境变量没有指定时生效。"""
        if directory and not self.log_dir_from_env:
            return Paths(self.home, self.config, self.state, Path(directory), False, self.singbox,
                         self.platform)
        return self

    @property
    def install_dir(self) -> Path:
        """sing-box 和启动器的安装目录。"""
        if self.platform == "nt":
            return Path(os.environ.get("ProgramFiles") or "C:/Program Files") / "norain-server"
        return Path("/usr/local/bin")

    @property
    def default_singbox(self) -> Path:
        return self.install_dir / ("sing-box.exe" if self.platform == "nt" else "sing-box")

    @property
    def reload_file(self) -> Path: return self.run_dir / "reload-request"
    @property
    def firewall_state(self) -> Path: return self.state / "firewall.json"
    @property
    def acme_dir(self) -> Path: return self.state / "acme"
    @property
    def install_record(self) -> Path: return self.state / "install.json"
    @property
    def cache_dir(self) -> Path: return self.state / "cache"

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
    def tls_dir(self) -> Path: return self.state / "tls"
    @property
    def secrets_dir(self) -> Path: return self.home / "secrets"
    @property
    def log_file(self) -> Path: return self.log_dir / "norain-server.log"
