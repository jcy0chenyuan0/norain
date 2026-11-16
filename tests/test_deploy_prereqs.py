"""安装器补齐前置依赖（venv / pip）的测试。

2026-11-16 在真实 Ubuntu 上部署时发现：norain-server install 只报缺口、不负责补齐，
而 Debian/Ubuntu 的 venv 和 pip 是分包的。现在安装器会在有 apt-get 且是 root 时自动装。
"""

import subprocess

import norain_server.deploy as deploy


def fake_run(rc: int):
    def run(args, **kwargs):
        return subprocess.CompletedProcess(args, rc, "", "")
    return run


def apt_host(monkeypatch, *, has_apt=True):
    monkeypatch.setattr(deploy.osutil, "IS_WINDOWS", False)
    monkeypatch.setattr(deploy.osutil, "is_admin", lambda: True)
    monkeypatch.setattr(deploy.shutil, "which",
                        lambda name: f"/usr/bin/{name}"
                        if name in ({"systemctl"} | ({"apt-get"} if has_apt else set())) else None)


def test_missing_venv_and_pip_are_installed_with_apt(monkeypatch):
    calls = []
    apt_host(monkeypatch)
    monkeypatch.setattr(deploy.osutil, "run", fake_run(1))
    monkeypatch.setattr(deploy.osutil, "run_checked", lambda args, **kw: calls.append(list(args)))

    steps, warnings = [], []
    deploy._ensure_prereqs(steps, warnings)

    installed = [c[-1] for c in calls]
    assert any("venv" in pkg for pkg in installed), installed
    assert "python3-pip" in installed
    assert steps and not warnings


def test_nothing_happens_when_dependencies_are_present(monkeypatch):
    calls = []
    apt_host(monkeypatch)
    monkeypatch.setattr(deploy.osutil, "run", fake_run(0))
    monkeypatch.setattr(deploy.osutil, "run_checked", lambda args, **kw: calls.append(list(args)))

    steps, warnings = [], []
    deploy._ensure_prereqs(steps, warnings)
    assert calls == [] and steps == [] and warnings == []


def test_non_apt_host_gets_a_manual_hint(monkeypatch):
    apt_host(monkeypatch, has_apt=False)
    monkeypatch.setattr(deploy.osutil, "run", fake_run(1))

    steps, warnings = [], []
    deploy._ensure_prereqs(steps, warnings)
    assert warnings and "前置依赖" in warnings[0]
