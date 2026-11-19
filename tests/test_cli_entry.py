"""命令行入口与 install 清理逻辑的回归测试。

2026-11-15 实测发现：
* `python -m norain.cli` 什么都不做还返回 0（模块末尾缺入口守卫）；
* `install.clear_system_proxy` 只把 ProxyEnable 置 0，不回填原来的 ProxyServer。
"""

import os
import subprocess
import sys
from pathlib import Path

from norain.install import clear_system_proxy
from norain.paths import Paths


def cli_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("NORAIN_")}
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    env["NORAIN_NO_SYSTEM_CHANGES"] = "1"
    return env


def test_client_module_entry_point_prints_help():
    proc = subprocess.run([sys.executable, "-m", "norain.cli", "--help"], env=cli_env(),
                          capture_output=True, encoding="utf-8", timeout=60)
    assert proc.returncode == 0
    assert "usage" in proc.stdout.lower() or "用法" in proc.stdout


def test_server_module_entry_point_prints_help():
    proc = subprocess.run([sys.executable, "-m", "norain_server.cli", "--help"], env=cli_env(),
                          capture_output=True, encoding="utf-8", timeout=60)
    assert proc.returncode == 0
    assert proc.stdout.strip()


def test_clear_system_proxy_restores_the_snapshot(tmp_path, monkeypatch):
    import norain_core.sysproxy as sp
    import norain.install as install

    paths = Paths(tmp_path, tmp_path / "cfg.toml", tmp_path / "state", tmp_path / "log", False, None, "nt")
    original = {"ProxyEnable": 0, "ProxyServer": "127.0.0.1:1082",
                "ProxyOverride": "*localhost", "AutoConfigURL": None}
    sp.save(paths.sysproxy_state, dict(original))
    written: list[dict] = []

    monkeypatch.setattr(install.osutil, "IS_WINDOWS", True)
    monkeypatch.setattr(install.osutil, "system_changes_disabled", lambda: False)
    monkeypatch.setattr(sp, "write", lambda values: written.append(dict(values)) or True)

    message = clear_system_proxy(paths)
    assert written and written[-1]["ProxyServer"] == "127.0.0.1:1082"
    assert message and "还原" in message
    assert not paths.sysproxy_state.exists()
