import json
import os

import pytest

from norain_core.errors import BIZ_CERT, BIZ_CONFIG, EXIT_CONFIG, NorainError
from norain_core.secrets import resolve
from norain_server import generate
from norain_server.model import load_config
from norain_server.paths import Paths

from conftest import PASSWORD


def errors_of(server, **kw):
    with pytest.raises(NorainError) as ei:
        load_config(server.config, env=kw.get("env", {}))
    assert ei.value.exit_code == EXIT_CONFIG and ei.value.business_code == BIZ_CONFIG
    return {f.path: f.message for f in ei.value.field_errors}


def test_valid_config_loads(server):
    cfg = load_config(server.config, env={})
    assert cfg.protocols.hysteria2.port == server.hy2_port and cfg.protocols.trojan.enabled


def test_unknown_field_is_rejected_with_suggestion(server):
    server.write_config(extra='[logging]\nlevle = "info"')
    errs = errors_of(server)
    assert "logging.levle" in errs and "level" in errs["logging.levle"]


def test_field_level_errors(server):
    server.config.write_text("""
[server]
domain = ""
listen = "not-an-ip"
[protocols.hysteria2]
enabled = false
port = 70000
[protocols.trojan]
enabled = false
[tls]
mode = "manual"
""")
    errs = errors_of(server)
    assert "protocols.hysteria2.port" in errs
    assert "server.listen" in errs
    # 类型错误先报；修好后才报跨字段错误
    server.config.write_text('[protocols.hysteria2]\nenabled = false\n[tls]\nmode = "manual"\n')
    errs = errors_of(server)
    assert {"protocols", "server.domain", "tls.certificate", "tls.private_key"} <= set(errs)


def test_acme_mode(server):
    # example.test 是域名：acme 可用，生成顶层 certificate_providers，不写内联 acme 和证书路径
    server.write_config(tls_mode="acme")
    cfg = load_config(server.config)
    doc = generate.build(cfg, PASSWORD, None, None, acme_dir=server.state / "acme")
    prov = doc["certificate_providers"][0]
    assert prov["type"] == "acme" and prov["domain"] == ["example.test"]
    assert prov["disable_tls_alpn_challenge"] is True   # Trojan 不在 443/tcp 上
    for ib in doc["inbounds"]:
        assert ib["tls"]["certificate_provider"] == prov["tag"]
        assert "certificate_path" not in ib["tls"] and "acme" not in ib["tls"]
    # 没有域名时不允许使用 acme
    server.write_config(tls_mode="acme", extra="")
    server.config.write_text(server.config.read_text().replace('"example.test"', '"203.0.113.9"'))
    assert "tls.mode" in errors_of(server)


def test_toml_syntax_error(server):
    server.config.write_text("[server\n")
    assert "(TOML 语法)" in errors_of(server)


def test_env_overrides(server):
    cfg = load_config(server.config, env={"NORAIN_HY2_PORT": "8443", "NORAIN_DOMAIN": "x.test"})
    assert cfg.protocols.hysteria2.port == 8443 and cfg.server.domain == "x.test"
    assert "环境变量 NORAIN_HY2_PORT" in errors_of(server, env={"NORAIN_HY2_PORT": "abc"})


def test_secret_missing_and_permissions(server):
    server.secret.chmod(0o644)
    with pytest.raises(NorainError) as ei:
        resolve(f"file:{server.secret}")
    assert "权限过宽" in ei.value.field_errors[0].message
    with pytest.raises(NorainError):
        resolve("file:/nonexistent/secret")
    with pytest.raises(NorainError):
        resolve("")
    with pytest.raises(NorainError):
        resolve("keyring:x/y")


def test_inline_password_requires_private_config(server):
    server.write_config(auth='password = "inline-pass-123"')
    assert load_config(server.config, env={}).auth.password == "inline-pass-123"
    server.config.chmod(0o644)
    assert "auth.password" in errors_of(server)


def test_generated_json_shape(server):
    cfg = load_config(server.config, env={})
    doc = generate.build(cfg, PASSWORD, server.state / "c.crt", server.state / "c.key")
    hy2, trojan = doc["inbounds"]
    assert hy2["type"] == "hysteria2" and hy2["listen_port"] == server.hy2_port
    assert trojan["type"] == "trojan" and "fallback" not in trojan
    for ib in doc["inbounds"]:
        assert ib["users"] == [{"name": "norain", "password": PASSWORD}]
        assert ib["tls"]["enabled"] and ib["tls"]["server_name"] == "example.test"
        assert "acme" not in ib["tls"]
    assert doc["outbounds"] == [{"type": "direct", "tag": "direct"}]
    assert doc["route"] == {"final": "direct"}


def test_single_protocol_and_fallback(server):
    server.write_config(extra="")
    text = server.config.read_text().replace(
        f"port = {server.trojan_port}",
        f"port = {server.trojan_port}\nfallback = {{ host = \"127.0.0.1\", port = 8080 }}")
    server.config.write_text(text)
    cfg = load_config(server.config, env={})
    doc = generate.build(cfg, PASSWORD, server.state / "c", server.state / "k")
    assert doc["inbounds"][1]["fallback"] == {"server": "127.0.0.1", "server_port": 8080}
    server.write_config(trojan=False)
    doc = generate.build(load_config(server.config, env={}), PASSWORD, server.state / "c", server.state / "k")
    assert [i["type"] for i in doc["inbounds"]] == ["hysteria2"]


def test_generation_is_deterministic(server):
    cfg = load_config(server.config, env={})
    a = generate.dumps(generate.build(cfg, PASSWORD, server.state / "c", server.state / "k"))
    b = generate.dumps(generate.build(cfg, PASSWORD, server.state / "c", server.state / "k"))
    assert a == b


def test_apply_is_atomic_and_keeps_backup(server, monkeypatch):
    paths = Paths.from_env()
    cfg = load_config(server.config, env={})
    secret = generate.resolve_secret(cfg)
    from conftest import FAKE
    first = generate.apply(cfg, secret, paths, FAKE)
    assert first.changed and first.backup is None
    assert oct(paths.current_json.stat().st_mode & 0o777) == "0o600"
    again = generate.apply(cfg, secret, paths, FAKE)
    assert not again.changed and again.version == first.version  # 幂等

    before = paths.current_json.read_bytes()
    server.write_config(trojan=False)
    cfg2 = load_config(server.config, env={})
    monkeypatch.setenv("FAKE_SB_CHECK_FAIL", "1")
    with pytest.raises(NorainError) as ei:
        generate.apply(cfg2, secret, paths, FAKE)
    assert PASSWORD not in ei.value.message and "***" in ei.value.message  # 脱敏
    assert paths.current_json.read_bytes() == before  # 校验失败不覆盖
    assert not list(paths.run_dir.glob(".candidate-*"))

    monkeypatch.delenv("FAKE_SB_CHECK_FAIL")
    third = generate.apply(cfg2, secret, paths, FAKE)
    assert third.changed and third.backup.read_bytes() == before
    assert json.loads(paths.meta_json.read_text())["config_version"] == third.version


def test_cert_checks(server, tmp_path):
    from norain_server import cert
    c, k = server.state / "tls" / "self-signed.crt", server.state / "tls" / "self-signed.key"
    ok = cert.check(c, k, "example.test")
    assert ok.ok and ok.self_signed and ok.days_left >= 363
    assert oct(k.stat().st_mode & 0o777) == "0o600"
    assert any("SAN" in e for e in cert.check(c, k, "other.test").errors)
    c2, k2 = tmp_path / "o.crt", tmp_path / "o.key"
    cert.self_signed("example.test", c2, k2)
    assert any("不匹配" in e for e in cert.check(c, k2, "example.test").errors)
    import datetime as dt
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=400)
    assert any("过期" in e for e in cert.check(c, k, "example.test", now=future).errors)
    missing = cert.check(tmp_path / "no.crt", tmp_path / "no.key", "example.test")
    assert len(missing.errors) == 2
    with pytest.raises(NorainError) as ei:
        missing.raise_if_invalid()
    assert ei.value.business_code == BIZ_CERT
    # 回退路径：没有 openssl 时用 cryptography 生成
    st = cert.check(*_python_cert(tmp_path), "10.0.0.1")
    assert st.ok


def _python_cert(tmp_path):
    from norain_server import cert
    c, k = tmp_path / "p.crt", tmp_path / "p.key"
    cert._generate_python("10.0.0.1", c, k, 30)
    return c, k
