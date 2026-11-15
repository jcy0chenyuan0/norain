"""常驻路径的开销和这次修掉的缺陷：原子写、日志、脱敏、监督循环、内控制的请求通道。

全部离线，不启动 sing-box，不碰系统设置（conftest 里设置了 NORAIN_NO_SYSTEM_CHANGES）。
"""

import json
import os
import threading
import time
import types

import pytest

from norain import control, probe
from norain.model import parse
from norain.paths import Paths as ClientPaths
from norain.routing import RETRY_COOLDOWN, Router
from norain.rules import Geo, due
from norain_core import atomic, cliutil, osutil, state
from norain_core.errors import NorainError
from norain_core.log import Logger, RotatingFile
from norain_core.redact import Redactor
from norain_core.supervisor import Spec, Supervisor


def client_paths(tmp_path) -> ClientPaths:
    return ClientPaths.from_env({"NORAIN_HOME": str(tmp_path), "NORAIN_STATE": str(tmp_path)}, platform="posix")


def client_cfg(**extra):
    return parse({"proxy": {"protocol": "trojan", "server": "s.example", "credential_ref": "env:X"}, **extra})


# ---- 测试保险 ------------------------------------------------------------------

def test_system_commands_are_disabled_in_tests():
    assert osutil.system_changes_disabled()
    for cmd in (["netsh", "advfirewall", "show", "allprofiles"], ["nft", "list", "ruleset"],
                ["schtasks", "/Query"], [r"C:\Windows\System32\netsh.EXE", "x"]):
        proc = osutil.run(cmd)
        assert proc.returncode == 126 and "NORAIN_NO_SYSTEM_CHANGES" in proc.stderr
    with pytest.raises(NorainError):
        osutil.run_checked(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], what="x")
    if osutil.IS_WINDOWS:
        with pytest.raises(NorainError):
            osutil._win_env_key(False, True)


# ---- 原子写 --------------------------------------------------------------------

def test_atomic_write_is_safe_across_threads_and_leaves_no_temp_files(tmp_path):
    target = tmp_path / "sub" / "state.json"     # 目录不存在时自动创建
    errors = []

    def writer(n):
        try:
            for i in range(40):
                state.write_json(target, {"writer": n, "i": i}, durable=False)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert state.read_json(target)["i"] == 39          # 最后留下的是一份完整的 JSON
    assert [p.name for p in target.parent.iterdir()] == ["state.json"]
    atomic.atomic_write(target, b"x" * 300_000)        # 大文件也完整写入
    assert target.read_bytes() == b"x" * 300_000


def test_op_lock_does_not_steal_a_lock_that_is_still_being_written(tmp_path):
    lock = tmp_path / "op.lock"
    lock.write_bytes(b"")          # 对方刚用 O_EXCL 建出文件，内容还没写
    with pytest.raises(NorainError) as ei:
        with state.op_lock(lock, op="start", op_id="b"):
            pass
    assert ei.value.retryable and lock.exists()
    old = time.time() - 60         # 空文件放久了才算失效锁，可以接管
    os.utime(lock, (old, old))
    with state.op_lock(lock, op="start", op_id="b"):
        assert json.loads(lock.read_text())["op_id"] == "b"
    assert not lock.exists()


# ---- 日志与脱敏 ----------------------------------------------------------------

def test_rotating_file_rotates_and_keeps_writing_when_rotation_fails(tmp_path, monkeypatch):
    path = tmp_path / "logs" / "norain.log"
    sink = RotatingFile(path, max_bytes=200, keep=2)
    assert sink._lock is RotatingFile(path, max_bytes=200, keep=2)._lock   # 同一文件共用一把锁
    for i in range(30):
        sink.write_line(f"line {i:03d} " + "x" * 20)
    names = sorted(p.name for p in path.parent.iterdir())
    assert names == ["norain.log", "norain.log.1", "norain.log.2"]
    assert all(p.stat().st_size <= 200 for p in path.parent.iterdir())
    assert path.read_text().splitlines()[-1].startswith("line 029")

    # 轮转失败（Windows 上日志正被 `logs -f` 打开）时不能丢日志
    monkeypatch.setattr(RotatingFile, "_rotate", lambda self: (_ for _ in ()).throw(PermissionError("busy")))
    before = path.stat().st_size
    for i in range(20):
        sink.write_line(f"kept {i}")
    assert path.stat().st_size > before and "kept 19" in path.read_text()


def test_redactor_fast_paths_keep_every_rule():
    r = Redactor()
    r.register("abc")
    r.register("abcdef-long-secret")
    r.register("abc")
    assert r._ordered == ("abcdef-long-secret", "abc")
    assert r.redact("x abcdef-long-secret y abc z") == "x *** y *** z"
    assert r.redact('{"password": "p1", "token":"t"}') == '{"password": ***, "token":***}'
    assert r.redact("PASSWD=hunter2 next") == "PASSWD=*** next"
    assert r.redact("mac_key: zzz, private_key='k'") == "mac_key: ***, private_key=***"
    assert r.redact("dial trojan://user:pw@host:443 failed") == "dial trojan://***@host:443 failed"
    pem = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----"
    assert r.redact(f"key {pem} end") == "key *** end"
    plain = "INFO [123 0ms] inbound/mixed[mixed-in]: inbound connection from 127.0.0.1:5000"
    assert r.redact(plain) is plain          # 普通日志行原样返回，不经过任何正则替换


def test_tail_reads_only_the_last_lines(tmp_path, capsys):
    log = tmp_path / "x.log"
    log.write_text("".join(f"l{i}\n" for i in range(1000)), encoding="utf-8")
    cliutil.tail(log, lines=3, follow=False)
    assert capsys.readouterr().out == "l997\nl998\nl999\n"
    cliutil.tail(log, lines=0, follow=False)
    assert capsys.readouterr().out == ""      # 以前 -n 0 会把整个日志打印出来


# ---- 监督循环 ------------------------------------------------------------------

def make_supervisor(tmp_path) -> Supervisor:
    run = tmp_path / "run"
    run.mkdir()
    return Supervisor(Spec(
        binary=tmp_path / "sing-box", config_json=run / "c.json", config_version="v", listeners=[],
        check_interval=1, restart_limit=1, backoff=0, log_file=tmp_path / "log" / "x.log",
        log_max_bytes=1 << 20, log_keep=2, log_level="info", runner_file=run / "runner.json",
        last_error_file=run / "err.json", stop_file=run / "stop"))


def test_supervisor_wait_wakes_on_stop_reload_and_stop_file(tmp_path):
    sup = make_supervisor(tmp_path)
    t0 = time.monotonic()
    assert sup._stop_requested(0.3) is False
    assert 0.25 <= time.monotonic() - t0 < 2

    # 重载请求立刻打断等待（以前要等到下一次 0.2 秒轮询；退避期间则要等整个退避时间）
    threading.Timer(0.1, sup.request_reload).start()
    t0 = time.monotonic()
    assert sup._stop_requested(30) is False and time.monotonic() - t0 < 5
    assert sup._reload_requested() is True and sup._reload_requested() is False

    # 停止请求文件在长等待期间也能及时生效（Windows 上只能靠它干净停止）
    threading.Timer(0.2, lambda: sup.spec.stop_file.write_text("x")).start()
    t0 = time.monotonic()
    assert sup._stop_requested(60) is True and time.monotonic() - t0 < 5

    (tmp_path / "b").mkdir()
    sup2 = make_supervisor(tmp_path / "b")
    threading.Timer(0.1, sup2.request_stop).start()
    t0 = time.monotonic()
    assert sup2._stop_requested(60) is True and time.monotonic() - t0 < 5


def test_supervisor_survives_a_failing_runner_file_write(tmp_path, monkeypatch):
    sup = make_supervisor(tmp_path)
    monkeypatch.setattr("norain_core.supervisor.write_json",
                        lambda *a, **k: (_ for _ in ()).throw(PermissionError("locked")))
    sup._write_runner(1234, 0, ready=True)    # 不抛异常：状态文件写不了不等于 sing-box 出了故障
    assert sup.ready is True


# ---- 内控制 --------------------------------------------------------------------

def bare_controller(tmp_path) -> control.Controller:
    paths = client_paths(tmp_path)
    paths.ctl_dir.mkdir(parents=True)
    ctl = control.Controller(paths)
    ctl.log = Logger("test", stderr=False)
    ctl._handle = lambda req: {"ok": True, "message": f"handled {req.get('op')}"}
    return ctl


def test_serve_survives_malformed_requests_and_cleans_stale_responses(tmp_path):
    ctl = bare_controller(tmp_path)
    d = ctl.paths.ctl_dir
    now = time.time()
    (d / "good.req.json").write_text(json.dumps({"op": "status", "id": "good", "at": now}))
    (d / "noid.req.json").write_text(json.dumps({"op": "status", "at": now}))     # 以前：KeyError 拖垮内控制
    (d / "list.req.json").write_text("[1, 2]")
    (d / "junk.req.json").write_text("{not json")
    (d / "badat.req.json").write_text(json.dumps({"op": "status", "at": "yesterday"}))
    (d / "old.req.json").write_text(json.dumps({"op": "status", "at": now - 3600}))
    (d / "stale.resp.json").write_text("{}")
    os.utime(d / "stale.resp.json", (now - 3600, now - 3600))
    (d / "fresh.resp.json").write_text("{}")

    ctl._serve()

    assert sorted(p.name for p in d.iterdir()) == ["fresh.resp.json", "good.resp.json", "noid.resp.json"]
    assert json.loads((d / "noid.resp.json").read_text())["message"] == "handled status"
    assert ctl.last_request["ok"] is True


def test_state_files_are_written_only_when_something_changed(tmp_path, monkeypatch):
    ctl = bare_controller(tmp_path)
    ctl.proxy = types.SimpleNamespace(child_pid=42, ready=True, restarts=0)
    ctl.status = lambda: {"updated_at": time.strftime("%H:%M:%S") + str(time.monotonic()), "phase": ctl.phase}
    ctl.paths.run_dir.mkdir(parents=True, exist_ok=True)
    writes = []
    real = control.write_json

    def counting(path, obj, **kw):
        assert kw.get("durable") is False       # 高频状态文件不 fsync
        writes.append(path.name)
        real(path, obj, **kw)

    monkeypatch.setattr(control, "write_json", counting)
    ctl._write_state()
    assert sorted(writes) == ["runner.json", "status.json"]
    for _ in range(5):
        ctl._write_state()
    assert len(writes) == 2                     # 状态没变：不再写盘
    ctl.phase = control.RUNNING_PHASE
    ctl._write_state()
    assert len(writes) == 4                     # 状态变了：两个文件都更新
    ctl.paths.runner.unlink()
    ctl._write_state()
    assert writes[-1] == "runner.json" and len(writes) == 5   # 被外部删掉的 runner 文件会补回来
    ctl._state_written_at = time.monotonic() - control.STATE_HEARTBEAT - 1
    ctl._write_state()
    assert len(writes) == 7                     # 心跳：隔一段时间即使没变化也刷新


# ---- 分流、规则集、探测 --------------------------------------------------------

def test_router_feed_filters_cheaply_and_bounds_its_memory(tmp_path):
    cfg = client_cfg(routing={"learn": True})
    router = Router(cfg, client_paths(tmp_path), classifier=None, log=Logger("t", stderr=False),
                    on_change=lambda: None)
    for line in ("INFO [1 0ms] inbound/mixed[mixed-in]: inbound connection from 127.0.0.1:1",
                 "INFO [1 0ms] dns: exchanged example.com", ""):
        router.feed(line)
    assert not router._conns and not router._fails
    # 带颜色的日志照样能识别
    router.feed("\x1b[36mINFO\x1b[0m [9 1ms] outbound/direct[direct]: outbound connection to a.example:443")
    assert router._conns == {"9": ("direct", "a.example")}
    for _ in range(2):
        router.feed("\x1b[36mINFO\x1b[0m [9 1ms] outbound/direct[direct]: outbound connection to a.example:443")
        router.feed("\x1b[31mERROR\x1b[0m [9 2ms] connection: open connection to a.example:443: i/o timeout")
    assert router._q.get_nowait() == "a.example"

    router._last = {f"old{i}.example": time.time() - RETRY_COOLDOWN - 5 for i in range(2500)}
    for _ in range(2):
        router.feed("[5] outbound/direct[direct]: outbound connection to b.example:443")
        router.feed("ERROR [5] failed")
    assert set(router._last) == {"b.example"}      # 过了冷却期的记录被清掉


def test_geo_cache_is_invalidated_when_the_rule_set_changes(tmp_path, monkeypatch):
    paths = client_paths(tmp_path)
    paths.rules_dir.mkdir(parents=True)
    f = paths.rules_dir / "geoip-cn.srs"
    f.write_bytes(b"SRS" + b"a" * 20)
    answers, calls = ["match\n"], []

    def fake_run(args, **k):
        calls.append(args[-1])
        return types.SimpleNamespace(returncode=0, stdout=answers[0], stderr="")

    monkeypatch.setattr("norain.rules.osutil.run", fake_run)
    geo = Geo(tmp_path / "sing-box", paths)
    assert geo.ip_is_home("1.2.3.4") is True and geo.ip_is_home("1.2.3.4") is True
    assert len(calls) == 1                         # 第二次走缓存，不再启动 sing-box
    answers[0] = "no match\n"
    f.write_bytes(b"SRS" + b"b" * 20)
    os.utime(f, ns=(time.time_ns() + 5_000_000_000,) * 2)
    assert geo.ip_is_home("1.2.3.4") is False and len(calls) == 2
    f.unlink()
    assert geo.ip_is_home("1.2.3.4") is None


def test_rules_due_tolerates_a_damaged_index(tmp_path):
    paths = client_paths(tmp_path)
    paths.rules_dir.mkdir(parents=True)
    cfg = client_cfg()
    assert due(cfg, paths) is True                 # 规则集文件缺失：立即更新
    for name in cfg.routing.rule_set:
        (paths.rules_dir / f"{name}.srs").write_bytes(b"SRS" + b"x" * 20)
    state.write_json(paths.rules_dir / "index.json", {"_checked_at": time.time()})
    assert due(cfg, paths) is False
    state.write_json(paths.rules_dir / "index.json", {"_checked_at": "garbage"})
    assert due(cfg, paths) is True                 # 以前：TypeError


def test_probe_reuses_tls_contexts_and_openers():
    import ssl
    strict, loose = probe._ssl_context(True), probe._ssl_context(False)
    assert strict is probe._ssl_context(True) and loose is probe._ssl_context(False)
    assert strict.verify_mode == ssl.CERT_REQUIRED and strict.check_hostname is True
    assert loose.verify_mode == ssl.CERT_NONE and strict is not loose
    px = ("127.0.0.1", 9)
    assert probe._opener(px, True) is probe._opener(("127.0.0.1", 9), True)
    assert probe._opener(px, True) is not probe._opener(px, False)
    assert probe._opener(None, True) is not probe._opener(px, True)
    # 行为不变：连不上本地入口时返回失败结果而不是抛异常（列表形式的入口也接受）
    r = probe.http("http://example.invalid/", proxy=["127.0.0.1", 9], timeout=1)
    assert r.ok is False and r.error
