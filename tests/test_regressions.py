"""离线回归用例：覆盖配置来源、生成转义和清理失败路径。"""

import tomllib

import pytest

from norain import install as client_install
from norain_core.errors import NorainError
from norain_core.log import Logger
from norain.routing import Router
from norain.paths import Paths as ClientPaths
from norain.model import parse
from norain.rules import Geo
from norain_server import cert, deploy
from norain_server.model import load_config
from norain_server.paths import Paths as ServerPaths


def test_server_password_environment_overrides_toml(tmp_path, monkeypatch):
    config = tmp_path / "server.toml"
    config.write_text(
        '[server]\ndomain = "example.test"\n'
        '[auth]\ncredential_ref = "file:/old/password"\n'
        '[tls]\nmode = "self-signed"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("NORAIN_PASSWORD", "from-environment")

    cfg = load_config(config, env={"NORAIN_PASSWORD": "from-environment"})

    assert cfg.auth.password == ""
    assert cfg.auth.credential_ref == "env:NORAIN_PASSWORD"


def test_server_config_without_password_source_is_rejected(tmp_path):
    config = tmp_path / "server.toml"
    config.write_text('[server]\ndomain = "example.test"\n[tls]\nmode = "self-signed"\n',
                      encoding="utf-8")

    with pytest.raises(NorainError) as exc:
        load_config(config, env={})

    assert any(f.path == "auth.credential_ref" for f in exc.value.field_errors)


def test_default_config_values_are_valid_toml():
    client_text = client_install.default_config_text(
        ClientPaths.from_env({"HOME": "/home/u"}, platform="posix"),
        server='host"with\\slash', credential_ref='file:C:/a"b/password',
        traffic_mode="mixed", protocol="trojan",
    )
    client_doc = tomllib.loads(client_text)
    assert client_doc["proxy"]["server"] == 'host"with\\slash'
    assert client_doc["proxy"]["credential_ref"] == 'file:C:/a"b/password'

    server_text = deploy.default_config_text(
        ServerPaths.from_env({"NORAIN_SERVER_HOME": "/tmp/norain"}, platform="posix"),
        {"NORAIN_DOMAIN": 'srv"name', "NORAIN_CERT_MODE": "acme",
         "NORAIN_ACME_EMAIL": 'a"b@example.test'},
        secret_ref='file:/tmp/a"b/password',
    )
    server_doc = tomllib.loads(server_text)
    assert server_doc["server"]["domain"] == 'srv"name'
    assert server_doc["auth"]["credential_ref"] == 'file:/tmp/a"b/password'
    assert server_doc["tls"]["email"] == 'a"b@example.test'


def test_default_lists_come_from_the_existing_proxy():
    from norain import defaults, generate, model

    text = client_install.default_config_text(
        ClientPaths.from_env({"HOME": "/home/u"}, platform="posix"),
        server="example.com", credential_ref="env:NORAIN_PASSWORD",
        traffic_mode="system-proxy", protocol="trojan",
    )
    doc = tomllib.loads(text)
    routing = doc["routing"]
    assert routing["proxy_domains"] == defaults.PROXY_DOMAINS
    assert routing["direct_domains"] == []
    assert routing["isolation_allowlist"] == defaults.ISOLATION_ALLOWLIST
    assert "openai.com" in routing["proxy_domains"]
    assert "deepseek.com" in routing["isolation_allowlist"]

    built = generate.build(model.parse(doc), password="x", rules={})
    trojan = next(o for o in built["outbounds"] if o["type"] == "trojan")
    # 原配置里客户端开了 smux，但服务端入站没开，mux 会让 trojan 连不上（2026-11-15 实测），
    # 所以默认不再往配置里写 multiplex。
    assert "multiplex" not in trojan


def test_default_server_config_rejects_non_numeric_port():
    with pytest.raises(NorainError) as exc:
        deploy.default_config_text(
            ServerPaths.from_env({"NORAIN_SERVER_HOME": "/tmp/norain"}, platform="posix"),
            {"NORAIN_HY2_PORT": "not-a-port"},
            secret_ref="file:/tmp/password",
        )

    assert "NORAIN_HY2_PORT" in exc.value.message


def test_client_install_persists_custom_state_path():
    paths = ClientPaths.from_env(
        {"NORAIN_HOME": "/home/u/norain", "NORAIN_CONFIG": "/tmp/cfg.toml",
         "NORAIN_STATE": "/tmp/norain-state"},
        platform="posix",
    )
    assert client_install._env(paths) == {
        "NORAIN_HOME": str(paths.home),
        "NORAIN_CONFIG": str(paths.config),
        "NORAIN_STATE": str(paths.state),
    }


def test_routing_learning_accepts_auto_mode_proxy_alt(tmp_path):
    cfg = parse({
        "proxy": {"protocol": "auto", "server": "s.example", "credential_ref": "env:X"},
        "routing": {"learn": True},
    })
    paths = ClientPaths.from_env(
        {"NORAIN_HOME": str(tmp_path), "NORAIN_STATE": str(tmp_path)}, platform="posix",
    )
    router = Router(cfg, paths, classifier=None, log=Logger("test", stderr=False), on_change=lambda: None)

    connection = "[7] outbound/foo[proxy-alt]: outbound connection to example.com:443"
    router.feed(connection)
    router.feed("ERROR [7] connection failed")
    router.feed(connection)
    router.feed("ERROR [7] connection failed")

    assert router._q.qsize() == 1


def test_geo_match_does_not_treat_no_match_as_true(tmp_path, monkeypatch):
    paths = ClientPaths.from_env(
        {"NORAIN_HOME": str(tmp_path), "NORAIN_STATE": str(tmp_path)}, platform="posix",
    )
    paths.rules_dir.mkdir()
    (paths.rules_dir / "geoip-cn.srs").write_bytes(b"SRS" + b"x" * 20)

    class Result:
        returncode = 0
        stdout = "no match\n"
        stderr = ""

    monkeypatch.setattr("norain.rules.osutil.run", lambda *a, **k: Result())
    assert Geo(tmp_path / "sing-box", paths).ip_is_home("203.0.113.1") is False


def test_uninstall_keeps_state_when_service_cannot_stop(tmp_path, monkeypatch):
    home = tmp_path / "home"
    state = tmp_path / "state"
    log = tmp_path / "log"
    home.mkdir()
    state.mkdir()
    log.mkdir()
    paths = ServerPaths(home, home / "server.toml", state, log, False, None, "posix")

    class Stuck:
        def stop(self):
            from norain_core.errors import NorainError

            raise NorainError("仍在运行", module="daemon")

    monkeypatch.setattr(deploy.osutil, "require_admin", lambda *a, **k: None)
    monkeypatch.setattr(deploy, "pick_backend", lambda _paths: Stuck())
    monkeypatch.setattr(deploy, "unregister_autostart", lambda: [])
    monkeypatch.setattr(deploy.firewall, "close_ports", lambda _paths: {"closed": []})
    monkeypatch.setattr(deploy.osutil, "unpersist_env", lambda *a, **k: [])
    monkeypatch.setattr(deploy.osutil, "remove_launcher", lambda *a, **k: False)

    result = deploy.uninstall(paths)

    assert result["errors"]
    assert state.exists()


def test_self_signed_falls_back_when_openssl_cannot_start(tmp_path, monkeypatch):
    monkeypatch.setattr(cert.shutil, "which", lambda _name: "openssl")
    monkeypatch.setattr(cert.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("not executable")))

    status, method = cert.self_signed(
        "example.test", tmp_path / "cert.pem", tmp_path / "key.pem", days=30,
    )

    assert method == "cryptography"
    assert status.ok
