import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Windows 不能直接启动带 shebang 的脚本，用 .cmd 转发到同一个假二进制
FAKE = ROOT / "tests" / "fakes" / ("sing-box.cmd" if os.name == "nt" else "sing-box")
PASSWORD = "s3cr3t-Pa55w0rd-for-tests"


def free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Env:
    """一套隔离的服务端环境：临时目录 + 模拟 sing-box + 自签证书。"""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.home, self.state, self.logs = tmp / "etc", tmp / "state", tmp / "log"
        for d in (self.home, self.state, self.logs):
            d.mkdir()
        self.config = self.home / "server.toml"
        self.secret = self.home / "password"
        self.secret.write_text(PASSWORD + "\n")
        self.secret.chmod(0o600)
        self.hy2_port = free_port(socket.SOCK_DGRAM)
        self.trojan_port = free_port()
        self.env = {
            **{k: v for k, v in os.environ.items() if not k.startswith(("NORAIN_", "FAKE_SB_"))},
            "NORAIN_SERVER_HOME": str(self.home), "NORAIN_SERVER_STATE": str(self.state),
            "NORAIN_SERVER_LOG": str(self.logs), "NORAIN_SERVER_SINGBOX": str(FAKE),
            "NORAIN_SERVER_BACKEND": "detached",
            "PYTHONPATH": str(ROOT / "src"),
        }
        self.write_config()

    def write_config(self, *, trojan=True, extra="", tls_mode="self-signed", interval=1,
                     limit=3, auth=None):
        # 写进 TOML 基本字符串的路径要用正斜杠：Windows 的 C:\Users\… 里 \U 会被
        # 当成 unicode 转义，tomllib 直接报 Invalid hex value
        auth = auth if auth is not None else f'credential_ref = "file:{self.secret.as_posix()}"'
        self.config.write_text(f"""
schema = 1
[server]
domain = "example.test"
listen = "127.0.0.1"
[protocols.hysteria2]
enabled = true
port = {self.hy2_port}
[protocols.trojan]
enabled = {str(trojan).lower()}
port = {self.trojan_port}
[auth]
{auth}
[tls]
mode = "{tls_mode}"
[service]
check_interval_seconds = {interval}
restart_limit = {limit}
restart_backoff_seconds = 0
{extra}
""")
        self.config.chmod(0o600)

    def cli(self, *args, env=None, timeout=60):
        proc = subprocess.run([sys.executable, "-m", "norain_server", *args],
                              env={**self.env, **(env or {})}, capture_output=True, text=True,
                              timeout=timeout)
        return proc

    def status(self, env=None) -> dict:
        return json.loads(self.cli("status", env=env).stdout)


@pytest.fixture
def server(tmp_path, monkeypatch):
    e = Env(tmp_path)
    for k in list(os.environ):
        if k.startswith(("NORAIN_", "FAKE_SB_")):
            monkeypatch.delenv(k)
    for k, v in e.env.items():
        if k.startswith("NORAIN_"):
            monkeypatch.setenv(k, v)
    r = e.cli("cert", "self-signed", "--domain", "example.test")
    assert r.returncode == 0, r.stderr
    yield e
    e.cli("stop")
