"""全仓审查（11 项问题）的回归测试：每项锁定当时的失败方式，防止再退化。

对应关系见 docs/pending.md 的审查记录；这里只放能用本机环境（无真实防火墙/Linux 服务）验证的部分。
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from norain import block, generate, probe, rules
from norain.model import parse
from norain_core import apply as core_apply
from norain_core import state
from norain_core.errors import NorainError


# ---- P1：探测不能绕过指定的代理 ------------------------------------------------

def test_probe_ignores_no_proxy_environment(monkeypatch):
    """指定了代理就必须走代理。NO_PROXY 命中时直连，结果却标记成 via="proxy"。"""
    requests = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("NO_PROXY", "127.0.0.1")
        monkeypatch.setenv("no_proxy", "127.0.0.1")
        probe._opener.cache_clear()
        # 代理端口上没有人监听：真的走了代理就必须失败
        url = f"http://127.0.0.1:{srv.server_address[1]}/"
        r = probe.http(url, proxy=("127.0.0.1", 1), via="proxy", timeout=2)
        assert not r.ok, "请求绕过了指定的代理并直连成功"
        r = probe.http(url, proxy=srv.server_address, via="proxy", timeout=2)
        assert r.ok and requests == [url]
    finally:
        srv.shutdown()
        srv.server_close()
        probe._opener.cache_clear()


# ---- P1：防火墙回滚失败后不能删状态记录 ------------------------------------------

class _BrokenFirewall:
    name = "fake"

    def __init__(self, cleanup_errors):
        self.cleanup_errors = cleanup_errors

    def snapshot(self):
        return {"Domain": True}

    def apply(self, v4, v6):
        raise NorainError("添加阻断规则失败", exit_code=1, module="block")

    def remove(self, st):
        return list(self.cleanup_errors)

    def present(self):
        return True


def _engage_with(tmp_path, monkeypatch, cleanup_errors):
    monkeypatch.setattr(block, "backend", lambda: _BrokenFirewall(cleanup_errors))
    monkeypatch.setattr(block.osutil, "require_admin", lambda *a, **k: None)
    monkeypatch.setattr(block, "proxy_only", lambda cfg: ([], [], {"resolved": {}, "unresolved": []}))
    monkeypatch.setattr(block, "allowed", block.proxy_only)

    class Paths:
        block_state = tmp_path / "block.json"

    with pytest.raises(NorainError):
        block.engage(None, Paths, code=602, reason="test", notify=False)
    return Paths.block_state


def test_block_keeps_state_when_rollback_leaves_rules(tmp_path, monkeypatch):
    st_file = _engage_with(tmp_path, monkeypatch, ["删除规则 Norain-Block-v4-0 失败：拒绝访问"])
    st = state.read_json(st_file)
    assert st is not None, "回滚没清理干净时不能删除阻断状态文件"
    assert st["cleanup_errors"]
    assert st["firewall_profiles"] == {"Domain": True}   # 原始防火墙状态也必须留着


def test_block_clears_state_when_rollback_is_clean(tmp_path, monkeypatch):
    assert not _engage_with(tmp_path, monkeypatch, []).exists()


def test_windows_cleanup_reports_failed_enumeration_and_profile_restore(monkeypatch):
    from types import SimpleNamespace

    failure = SimpleNamespace(returncode=1, stderr="Access denied", stdout="")
    monkeypatch.setattr(block.osutil, "powershell", lambda script: failure)
    monkeypatch.setattr(block.osutil, "run", lambda args: failure)
    errors = block.WindowsBackend().remove({"rules": [], "firewall_profiles": {"Private": False}})
    assert len(errors) == 2


# ---- P2：操作锁到期后可被同时接管 ----------------------------------------------

def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def test_live_lock_cannot_be_taken_over(tmp_path):
    lock = tmp_path / "op.lock"
    with state.op_lock(lock, op="first", op_id="a", timeout=0.01):
        time.sleep(0.05)
        with pytest.raises(NorainError):
            with state.op_lock(lock, op="second", op_id="b", timeout=0.01):
                pass
    assert not lock.exists()


def test_dead_lock_is_taken_over(tmp_path):
    lock = tmp_path / "op.lock"
    lock.write_text(json.dumps({"op": "dead", "op_id": "x", "pid": _dead_pid(),
                                "expires_at": time.time() + 600}), encoding="utf-8")
    with state.op_lock(lock, op="next", op_id="y", timeout=10):
        assert (state.read_json(lock) or {}).get("op_id") == "y"


def test_os_lock_releases_when_holder_exits(tmp_path):
    lock = tmp_path / "op.lock"
    from harness_singbox import wait_for

    code = (
        "import sys,time\n"
        "from pathlib import Path\n"
        "from norain_core.state import op_lock\n"
        "with op_lock(Path(sys.argv[1]), op='child', op_id='child'):\n"
        "    time.sleep(30)\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(state.__file__).resolve().parents[1])}
    proc = subprocess.Popen([sys.executable, "-c", code, str(lock)], env=env)
    try:
        assert wait_for(lambda: (state.lock_holder(lock) or {}).get("op_id") == "child")
        with pytest.raises(NorainError):
            with state.op_lock(lock, op="parent", op_id="parent"):
                pass
    finally:
        proc.kill()
        proc.wait(timeout=5)
    with state.op_lock(lock, op="parent", op_id="parent"):
        assert state.lock_holder(lock)["op_id"] == "parent"


# ---- P2：配置应用失败后新配置不应已经生效 ----------------------------------------

def test_apply_rolls_back_when_metadata_write_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(core_apply.singbox, "check", lambda binary, path: None)
    run, current, backups, source = (tmp_path / "run", tmp_path / "current.json",
                                     tmp_path / "backups", tmp_path / "src.toml")
    run.mkdir()
    backups.mkdir()
    source.write_text("x", encoding="utf-8")
    current.write_text('{"old": true}', encoding="utf-8")
    meta = tmp_path / "meta.json"
    meta.write_text('{"version": "old"}', encoding="utf-8")

    def boom(path, obj, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(core_apply, "write_json", boom)
    with pytest.raises(OSError):
        core_apply.apply(b'{"new": true}', run_dir=run, current=current, backups=backups,
                         meta=meta, source=source, schema=1, binary=Path("sing-box"))
    assert current.read_text() == '{"old": true}'
    assert meta.read_text() == '{"version": "old"}'


# ---- P2：损坏的规则集不能被启用 ------------------------------------------------

def _client_cfg(tmp_path, **routing):
    return parse({"proxy": {"protocol": "trojan", "server": "203.0.113.10", "credential_ref": "env:X"},
                  "routing": dict(routing)})


def test_rules_update_rejects_rule_set_sing_box_cannot_load(tmp_path, monkeypatch):
    def downloader(url, dest, proxy, timeout):
        # 文件头和长度都合法，只有内容坏掉：旧实现会把它替换上线
        dest.write_bytes(b"SRS" + b"\x00" * 64)

    class Paths:
        home = tmp_path
        rules_dir = tmp_path / "rules"

    Paths.rules_dir.mkdir()
    old = b"SRS" + b"\x01" * 64
    (Paths.rules_dir / "geoip-cn.srs").write_bytes(old)

    calls = []

    def verify(binary, path):
        calls.append(path)
        raise OSError("sing-box 无法加载规则集：unexpected EOF")

    monkeypatch.setattr(rules, "_verify", verify)
    rep = rules.update(_client_cfg(tmp_path, rule_set=["geoip-cn"]), Paths,
                       downloader=downloader, binary=Path("sing-box"))
    assert calls, "更新流程必须调用结构校验"
    assert "geoip-cn" in rep["failed"]
    assert (Paths.rules_dir / "geoip-cn.srs").read_bytes() == old


def test_rules_update_accepts_compiled_srs_and_keeps_it_on_failure(tmp_path):
    from types import SimpleNamespace

    from harness_singbox import find_singbox

    binary = find_singbox()
    if not binary:
        pytest.skip("需要真实 sing-box")
    source = tmp_path / "rules.json"
    source.write_text(json.dumps({"version": 3, "rules": [{"domain": ["example.test"]}]}), encoding="utf-8")
    compiled = tmp_path / "compiled.srs"
    subprocess.run([binary, "rule-set", "compile", "--output", str(compiled), str(source)], check=True, timeout=10)
    cfg = _client_cfg(tmp_path, rule_set=["geosite-cn"])
    paths = SimpleNamespace(home=tmp_path, rules_dir=tmp_path / "rules")
    data = compiled.read_bytes()
    report = rules.update(cfg, paths, binary=Path(binary),
                          downloader=lambda url, dest, *_: dest.write_bytes(data))
    assert report["updated"] == ["geosite-cn"], report
    report = rules.update(cfg, paths, binary=Path(binary),
                          downloader=lambda url, dest, *_: dest.write_bytes(b"SRS" + bytes(64)))
    assert "geosite-cn" in report["failed"]
    assert rules.path_of(paths, "geosite-cn").read_bytes() == data


# ---- P2：关闭 / 启用 fake-IP 时学习缓存不能抢在显式规则前 ----------------------

@pytest.mark.parametrize("fake_ip", [False, True])
def test_hosts_cache_rules_come_after_explicit_lists(tmp_path, fake_ip):
    cfg = _client_cfg(tmp_path, proxy_domains=["a.example"], direct_domains=["b.example"])
    cfg.proxy.traffic_mode = "tun"
    cfg.dns.fake_ip = fake_ip
    learned = {"hosts": {"b.example": ["1.2.3.4"]}, "proxy": ["d.example"], "direct": ["e.example"]}
    dns, _ = generate._dns(cfg, learned, [], "prefer_ipv4")
    servers = [r.get("server") for r in dns["rules"]]
    assert "dns-hosts" in servers
    hosts_at = servers.index("dns-hosts")
    assert servers.index("dns-direct") < hosts_at   # 显式直连名单（含代理服务器域名）
    assert servers.index("dns-proxy") < hosts_at    # 显式代理名单


# ---- P2：服务端更新失败时运行配置也要一起回滚 --------------------------------

def test_update_rollback_restores_running_config(tmp_path, monkeypatch):
    """新版本启动失败时只还原二进制是不够的：运行 JSON 还是新版生成的，
    重试会用旧程序加载新配置，再次失败。"""
    import norain_server.deploy as deploy

    home = tmp_path / "home"
    state = tmp_path / "state"
    for d in (home, state, state / "run"):
        d.mkdir(parents=True)
    config = home / "server.toml"
    config.write_text("schema = 1\n", encoding="utf-8")
    old_bin = home / "sing-box"
    old_bin.write_bytes(b"old-binary")
    current = state / "run" / "sing-box.json"
    current.write_text('{"old": true}', encoding="utf-8")
    meta = state / "run" / "sing-box.json.meta.json"
    meta.write_text('{"config_version": "old"}', encoding="utf-8")

    class Paths:
        pass

    p = Paths()
    p.home, p.state = home, state
    p.config, p.backups, p.desired, p.secrets_dir, p.tls_dir, p.acme_dir = (
        config, state / "backups", state / "desired.json", home / "secrets", home / "tls", home / "acme")
    p.cache_dir, p.default_singbox = tmp_path / "cache", old_bin
    p.current_json, p.meta_json, p.run_dir = current, meta, state / "run"
    p.recovery_file = p.run_dir / "use-current-config"

    starts = []

    class Backend2:
        def stop(self):
            pass

        def start(self):
            starts.append(1)
            if len(starts) == 1:
                raise NorainError("启动失败", exit_code=1, module="daemon")
            assert p.recovery_file.read_text() == core_apply.version_of(current.read_bytes())

    monkeypatch.setattr(deploy.osutil, "require_admin", lambda *a, **k: None)
    monkeypatch.setattr(deploy, "backup_user_data", lambda paths: _make_backup(tmp_path, paths))
    monkeypatch.setattr(deploy, "load_config", lambda path: None)
    monkeypatch.setattr(deploy, "get_desired", lambda path: "running")
    def install(candidate, *args, **kwargs):
        assert old_bin.read_bytes() == b"old-binary"
        candidate.write_bytes(b"new-binary")
        return _Info()

    monkeypatch.setattr(deploy.fetch, "install_singbox", install)
    monkeypatch.setattr(deploy.runner, "need_tags", lambda cfg: set())
    monkeypatch.setattr(deploy.runner, "prepare", lambda paths, apply=False: _Stall(current))
    monkeypatch.setattr(deploy, "register_autostart", lambda paths: "ok")
    monkeypatch.setattr(deploy, "sync_ownership", lambda paths: None)
    monkeypatch.setattr(deploy, "pick_backend", lambda paths: Backend2())

    with pytest.raises(NorainError, match="启动失败"):
        deploy.update(p, singbox_path=old_bin)

    assert current.read_text(encoding="utf-8") == '{"old": true}'
    assert meta.read_text(encoding="utf-8") == '{"config_version": "old"}'
    assert old_bin.read_bytes() == b"old-binary"
    assert len(starts) == 2


class _Info:
    version = "1.14.4"


class _Stall:
    """冒充 prepare 的结果：它会把运行配置换成新版内容，然后 update 在启动时失败。"""

    def __init__(self, current):
        self.current = current

    @property
    def applied(self):
        self.current.write_text('{"new": true}', encoding="utf-8")
        return type("R", (), {"version": "new"})()


def _make_backup(tmp_path, paths):
    from pathlib import Path
    import shutil
    dest = Path(tmp_path) / "backup"
    dest.mkdir(exist_ok=True)
    shutil.copy2(paths.default_singbox, dest / paths.default_singbox.name)
    return dest
