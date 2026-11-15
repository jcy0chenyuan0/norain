import json
import os
import tomllib

import pytest

from norain_core import singbox, state
from norain_core.errors import EXIT_CONFLICT, EXIT_DEPENDENCY, NorainError
from norain_core.log import Logger, RotatingFile
from norain_core.redact import Redactor

from conftest import FAKE, ROOT


def test_redaction():
    r = Redactor()
    r.register("hunter2-long-secret")
    text = r.redact('auth failed for hunter2-long-secret; url trojan://abc123@example.com:443 '
                    '"password": "zzz" -----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----')
    for leaked in ("hunter2", "abc123", "zzz", "MIIB"):
        assert leaked not in text
    assert "example.com:443" in text
    assert r.redact_obj({"password": "x", "nested": [{"token": "y", "port": 1}]}) == {
        "password": "***", "nested": [{"token": "***", "port": 1}]}


def test_logger_redacts_and_rotates(tmp_path):
    from norain_core.redact import REDACTOR
    REDACTOR.register("log-secret-value")
    sink = RotatingFile(tmp_path / "a.log", max_bytes=400, keep=2)
    log = Logger("t", sink=sink, stderr=False)
    for i in range(20):
        log.info("evt", msg=f"n={i} log-secret-value")
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == ["a.log", "a.log.1", "a.log.2"]
    for p in tmp_path.iterdir():
        assert "log-secret-value" not in p.read_text()
    rec = json.loads((tmp_path / "a.log").read_text().splitlines()[-1])
    assert {"time", "level", "module", "op_id", "event", "detail"} <= set(rec)


def test_desired_state_and_lock(tmp_path):
    d = tmp_path / "desired.json"
    assert state.get_desired(d) == state.STOPPED
    state.set_desired(d, state.RUNNING, op_id="a")
    assert state.get_desired(d) == state.RUNNING

    lock = tmp_path / "op.lock"
    with state.op_lock(lock, op="start", op_id="1"):
        with pytest.raises(NorainError) as ei:
            with state.op_lock(lock, op="stop", op_id="2"):
                pass
        assert ei.value.exit_code == EXIT_CONFLICT
    assert not lock.exists()
    # 持锁进程已死或锁过期时可以接管
    lock.write_text(json.dumps({"op": "x", "op_id": "dead", "pid": 2 ** 22 + 12345, "expires_at": 9e12}))
    with state.op_lock(lock, op="start", op_id="3"):
        pass
    lock.write_text(json.dumps({"op": "x", "op_id": "old", "pid": os.getpid(), "expires_at": 1}))
    with state.op_lock(lock, op="start", op_id="4"):
        pass


def test_pinned_version_matches_lockfile():
    lock = tomllib.loads((ROOT / "third_party" / "singbox.lock.toml").read_text(encoding="utf-8"))
    assert lock["singbox"]["version"] == singbox.PINNED_VERSION


def test_binary_inspect_and_require(monkeypatch, tmp_path):
    info = singbox.inspect(FAKE)
    assert info.version == "1.14.4" and "with_quic" in info.tags
    singbox.require(info, need_tags={"with_quic"})
    monkeypatch.setenv("FAKE_SB_VERSION", "1.13.0")
    with pytest.raises(NorainError) as ei:
        singbox.require(singbox.inspect(FAKE), need_tags=set())
    assert ei.value.exit_code == EXIT_DEPENDENCY and ei.value.business_code == 150
    monkeypatch.delenv("FAKE_SB_VERSION")
    monkeypatch.setenv("FAKE_SB_TAGS", "with_utls")
    with pytest.raises(NorainError):
        singbox.require(singbox.inspect(FAKE), need_tags={"with_quic"})
    with pytest.raises(NorainError) as ei:
        singbox.locate(str(tmp_path / "missing"))
    assert ei.value.business_code == 150
