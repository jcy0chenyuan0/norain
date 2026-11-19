"""用模拟 sing-box 走完整的 CLI 链路。这些测试验证 Norain 自身的控制逻辑，
不代表真实 sing-box 接受生成的配置。"""

import json
import socket
import subprocess
import time

import psutil
import pytest

from norain_core.errors import NorainError
from norain_server.service import SystemdBackend, UNIT

from conftest import PASSWORD, free_port


def wait_for(fn, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.2)
    raise AssertionError("超时")


@pytest.mark.slow
def test_validate_start_status_stop_chain(server):
    r = server.cli("config", "validate", "--json")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["singbox_version"] == "1.14.4"

    r = server.cli("start")
    assert r.returncode == 0, r.stderr
    st = server.status()
    assert st["service"]["state"] == "running" and st["process"]["running"]
    assert st["business_code"] == 0 and st["desired"] == "running"
    assert {p["name"] for p in st["protocols"]} == {"hysteria2", "trojan"}
    assert st["cert"]["ok"] and st["config"]["version"] and st["restarts"] == 0
    with socket.create_connection(("127.0.0.1", server.trojan_port), timeout=3):
        pass
    assert server.cli("start").returncode == 0  # 幂等
    assert server.status()["service"]["pid"] == st["service"]["pid"]

    # 秘密不出现在任何输出和日志里
    out = server.cli("config", "show").stdout + json.dumps(st) + server.cli("log").stdout
    assert PASSWORD not in out
    for p in server.logs.iterdir():
        assert PASSWORD not in p.read_text(encoding="utf-8", errors="replace")

    child = st["process"]["pid"]
    assert server.cli("stop").returncode == 0
    st = server.status()
    assert st["service"]["state"] == "stopped" and st["desired"] == "stopped"
    assert st["business_code"] == 0
    assert not psutil.pid_exists(child) or psutil.Process(child).status() == psutil.STATUS_ZOMBIE
    assert server.cli("stop").returncode == 0  # 幂等
    time.sleep(2.5)  # 超过检查间隔：手动停止后没有任何东西把它拉起来
    assert server.status()["service"]["state"] == "stopped"
    assert server.cli("_desired-state-is", "running").returncode == 1


@pytest.mark.slow
def test_crashed_singbox_is_restarted_then_stays_up(server):
    # 第一次启动崩溃，守护自动重启后就绪，start 最终成功
    assert server.cli("start", env={"FAKE_SB_CRASH_ONCE": str(server.tmp / "crashed")}).returncode == 0
    st = wait_for(lambda: (s := server.status())["process"]["running"] and s)
    assert st["restarts"] == 1 and st["business_code"] == 0
    assert st["last_error"]["business_code"] == 140  # 保留最近错误


@pytest.mark.slow
def test_restart_limit_stops_restarting(server):
    server.write_config(limit=2)
    r = server.cli("start", env={"FAKE_SB_CRASH": "1"})
    assert r.returncode != 0
    st = wait_for(lambda: (s := server.status())["service"]["state"] == "stopped" and s)
    assert st["business_code"] == 160 and st["desired"] == "running"
    log = (server.logs / "norain-server.log").read_text(encoding="utf-8", errors="replace")
    assert log.count('"singbox.started"') == 3  # 首次 + 2 次重启
    assert '"daemon.restart_limit"' in log


@pytest.mark.slow
def test_health_check_detects_missing_listener_and_fatal(server):
    server.write_config(limit=0)
    r = server.cli("start", "--json", env={"FAKE_SB_NO_LISTEN": "1"})
    assert r.returncode != 0  # 从未就绪，start 不能报成功
    st = wait_for(lambda: (s := server.status())["service"]["state"] == "stopped" and s)
    assert "端口没有在监听" in (server.logs / "norain-server.log").read_text(encoding="utf-8", errors="replace")
    assert st["business_code"] == 160
    server.cli("stop")
    server.cli("start", env={"FAKE_SB_FATAL": "1"})
    wait_for(lambda: "日志出现 fatal" in (server.logs / "norain-server.log").read_text(encoding="utf-8", errors="replace"))


@pytest.mark.slow
def test_start_refuses_bad_config_and_port_in_use(server):
    server.write_config(tls_mode="manual")
    r = server.cli("start", "--json")
    body = json.loads(r.stdout)
    assert r.returncode == 3 and body["business_code"] == 110
    assert {f["path"] for f in body["field_errors"]} == {"tls.certificate", "tls.private_key"}
    assert server.status()["desired"] == "stopped"  # 预检失败不改变期望状态

    server.write_config()
    with socket.socket() as s:
        s.bind(("127.0.0.1", server.trojan_port))
        s.listen()
        r = server.cli("start", "--json")
        assert json.loads(r.stdout)["business_code"] == 130

    r = server.cli("start", "--json", env={"NORAIN_SERVER_SINGBOX": "/nonexistent/sing-box"})
    assert r.returncode == 5 and json.loads(r.stdout)["business_code"] == 150


@pytest.mark.slow
def test_reload_moves_to_new_port_without_killing_daemon(server):
    """重载换了端口之后，守护进程不能还在检查旧端口——那会一路重启到上限并退出。"""
    assert server.cli("start").returncode == 0
    server.trojan_port = free_port()
    server.write_config()
    r = server.cli("reload", "--json")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["reloaded"] is True
    st = wait_for(lambda: (s := server.status())["process"]["running"] and s)
    assert st["service"]["state"] == "running"
    assert st["business_code"] == 0
    with socket.create_connection(("127.0.0.1", server.trojan_port), timeout=3):
        pass   # 新端口在监听
    time.sleep(3)   # 跨过至少两个健康检查周期
    st = server.status()
    assert st["service"]["state"] == "running" and st["business_code"] == 0


def test_reload_refuses_occupied_port_without_replacing_running_config(server):
    assert server.cli("start").returncode == 0
    old = server.status()
    run = server.state / "run" / "sing-box.json"
    active = run.read_bytes()
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        server.trojan_port = busy.getsockname()[1]
        server.write_config()
        result = server.cli("reload", "--json")
        assert result.returncode != 0
        assert json.loads(result.stdout)["business_code"] == 130
    assert run.read_bytes() == active
    assert server.status()["process"]["pid"] == old["process"]["pid"]


def test_rollback_restart_uses_saved_runtime_instead_of_edited_toml(server, monkeypatch):
    from norain_server import runner
    from norain_server.paths import Paths

    paths = Paths.from_env()
    prep = runner.prepare(paths)
    saved = paths.current_json.read_bytes()
    saved_meta = paths.meta_json.read_bytes()
    old_port = server.trojan_port
    server.trojan_port = free_port()
    server.write_config()
    runner.restore_runtime(paths, saved, saved_meta)

    def run(supervisor):
        assert ("127.0.0.1", "tcp", old_port) in supervisor.spec.listeners
        assert supervisor.spec.config_version == prep.applied.version
        assert paths.current_json.read_bytes() == saved
        return 0

    monkeypatch.setattr(runner.Supervisor, "run", run)
    assert runner.run_foreground(paths) == 0


@pytest.mark.slow
def test_restart_keeps_old_process_when_new_config_invalid(server):
    assert server.cli("start").returncode == 0
    pid = server.status()["process"]["pid"]
    server.write_config(extra="[bogus]\nx = 1")
    assert server.cli("restart").returncode == 3
    st = server.status()
    assert st["process"]["pid"] == pid and st["service"]["state"] == "running"
    assert st["config"]["valid"] is False
    server.write_config(trojan=False)
    assert server.cli("restart").returncode == 0
    st = server.status()
    assert st["process"]["pid"] != pid and len(st["protocols"]) == 1
    assert len(list((server.state / "backups").iterdir())) == 1


def test_firewall_status_lists_only_enabled_ports(server):
    # 只测只读的 status：open/close 会真的修改系统防火墙，只能在一次性虚拟机里验证
    r = server.cli("firewall", "status", "--json")
    body = json.loads(r.stdout)
    assert {row["port"] for row in body["ports"]} == {f"{server.hy2_port}/udp", f"{server.trojan_port}/tcp"}
    assert all(row["managed_by_norain"] is False for row in body["ports"])


def test_systemd_backend_with_fake_systemctl(server):
    from norain_server.paths import Paths
    calls = []

    def run(args):
        calls.append(args)
        out = "ActiveState=failed\nMainPID=0\nNRestarts=2\n" if args[1] == "show" else ""
        rc = 1 if args[1] == "stop" else 0
        return subprocess.CompletedProcess(args, rc, out, "Access denied" if rc else "")

    b = SystemdBackend(Paths.from_env(), run)
    # systemctl start 返回 0 但服务其实是 failed：不能报成功
    with pytest.raises(NorainError) as exc:
        b.start()
    assert "没有在运行" in exc.value.message
    assert [c[1] for c in calls] == ["reset-failed", "start", "show"]
    st = b.status()
    assert st.state == "failed" and st.outer_restarts == 2
    try:
        b.stop()
        raise AssertionError
    except NorainError as e:
        assert e.exit_code == 4
    assert calls[-1] == ["systemctl", "stop", UNIT]


def test_systemd_backend_start_requires_ready_child(server, monkeypatch):
    from norain_server.paths import Paths
    from norain_server import service

    calls = []

    def run(args):
        calls.append(args[1])
        out = "ActiveState=active\nMainPID=42\nNRestarts=0\n" if args[1] == "show" else ""
        return subprocess.CompletedProcess(args, 0, out, "")

    b = SystemdBackend(Paths.from_env(), run)
    with pytest.raises(NorainError, match="未就绪"):
        b.start(timeout=0)
    assert calls[-1] == "stop"
    monkeypatch.setattr(service, "runner_info", lambda path: {"pid": 42, "ready": True, "child_pid": 43})
    monkeypatch.setattr(service, "alive", lambda pid: pid == 43)
    b.start()
    assert b.status().state == "running"
