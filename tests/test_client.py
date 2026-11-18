"""客户端（阶段 2）测试。生命周期部分使用模拟 sing-box。"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from norain import generate
from norain.model import load_config
from norain.paths import Paths
from norain_core.errors import NorainError

from conftest import FAKE, PASSWORD, ROOT, free_port


class Client:
    def __init__(self, tmp: Path):
        self.tmp, self.home, self.state = tmp, tmp / "cfg", tmp / "state"
        self.home.mkdir()
        self.state.mkdir()
        self.config = self.home / "cfg.toml"
        self.secret = self.home / "password"
        self.secret.write_text(PASSWORD + "\n")
        self.secret.chmod(0o600)
        self.port = free_port()
        self.env = {**{k: v for k, v in os.environ.items() if not k.startswith(("NORAIN_", "FAKE_SB_"))},
                    "NORAIN_HOME": str(self.home), "NORAIN_STATE": str(self.state),
                    "NORAIN_SINGBOX": str(FAKE), "PYTHONPATH": str(ROOT / "src"),
                    "NORAIN_NO_SYSTEM_CHANGES": "1"}
        self.write()

    # 生命周期测试要离线可跑：关掉监控、看门狗、分流学习和规则集（它们会访问真实网络）
    BASE = """
[monitor]
enabled = false
[maintain]
watchdog = false
block_on_failure = false
[routing]
learn = false
rule_set = []
[dns]
mode = "local"
"""

    def write(self, *, protocol="hysteria2", extra="", proxy_extra="", limit=3, base=True):
        self.config.write_text(f"""
schema = 1
[local]
port = {self.port}
[proxy]
protocol = "{protocol}"
server = "example.test"
credential_ref = "file:{self.secret.as_posix()}"
{proxy_extra}
[proxy.trojan]
port = 8443
[supervisor]
check_interval_seconds = 1
restart_limit = {limit}
backoff_seconds = 0
{self.BASE if base else ""}
{extra}
""")
        self.config.chmod(0o600)

    def cli(self, *args, env=None):
        return subprocess.run([sys.executable, "-m", "norain", *args], env={**self.env, **(env or {})},
                              capture_output=True, text=True, timeout=60)

    def status(self):
        return json.loads(self.cli("status", "--json").stdout)


@pytest.fixture
def client(tmp_path):
    c = Client(tmp_path)
    yield c
    c.cli("stop")


def errs(client):
    with pytest.raises(NorainError) as ei:
        load_config(client.config)
    return {f.path: f.message for f in ei.value.field_errors}


def test_generated_json(client):
    cfg = load_config(client.config)
    doc = generate.build(cfg, PASSWORD)
    assert doc["inbounds"] == [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
                                "listen_port": client.port}]
    proxy, direct = doc["outbounds"]
    assert proxy["type"] == "hysteria2" and proxy["server_port"] == 443
    assert proxy["password"] == PASSWORD and proxy["tls"]["server_name"] == "example.test"
    assert "insecure" not in proxy["tls"]
    assert direct == {"type": "direct", "tag": "direct"}
    assert doc["route"]["final"] == "proxy"  # 未命中任何规则的流量默认走代理
    assert doc["dns"]["servers"] == [{"type": "local", "tag": "local"}]
    assert generate.render(cfg, generate.resolve_secret(cfg)) == generate.render(cfg, generate.resolve_secret(cfg))

    client.write(protocol="trojan")
    proxy = generate.build(load_config(client.config), PASSWORD)["outbounds"][0]
    assert proxy["type"] == "trojan" and proxy["server_port"] == 8443 and "alpn" not in proxy["tls"]


def test_unimplemented_values_are_rejected(client):
    # 目前唯一没有实现的取值是 transparent
    client.write(proxy_extra='traffic_mode = "transparent"')
    e = errs(client)
    assert "尚未实现" in e["proxy.traffic_mode"]
    # 同一条目同时在白名单和黑名单里：直接报错
    client.write(base=False, extra='[routing]\nproxy_domains = ["a.com"]\ndirect_domains = ["a.com"]')
    assert "routing" in errs(client)


def test_full_config_generation(client):
    """auto + tun + split DNS + 名单：只检查生成的结构，不启动任何东西。"""
    client.write(protocol="auto", proxy_extra='traffic_mode = "tun"', base=False,
                 extra='[routing]\nproxy_domains = ["google.com", "full:a.example"]\n'
                       'direct_domains = ["baidu.com", "10.9.0.0/16"]')
    cfg = load_config(client.config)
    rules = {"geosite-cn": Path("/r/geosite-cn.srs"), "geoip-cn": Path("/r/geoip-cn.srs")}
    doc = generate.build(cfg, PASSWORD, active="trojan", rules=rules,
                         learned={"proxy": ["learned.example"], "direct": [], "hosts": {"h.example": ["192.0.2.1"]}})
    tags = [o["tag"] for o in doc["outbounds"]]
    assert tags == ["proxy", "proxy-alt", "direct"]
    assert doc["outbounds"][0]["type"] == "trojan" and doc["outbounds"][1]["type"] == "hysteria2"
    kinds = {i["tag"]: i["type"] for i in doc["inbounds"]}
    assert kinds["tun-in"] == "tun" and {"probe-direct", "probe-hysteria2", "probe-trojan"} <= set(kinds)
    assert "stack" not in next(i for i in doc["inbounds"] if i["type"] == "tun")
    rr = doc["route"]["rules"]
    assert {"protocol": "dns", "action": "hijack-dns"} in rr
    assert {"inbound": "probe-hysteria2", "action": "route", "outbound": "proxy-alt"} in rr
    order = [r.get("outbound") for r in rr if "domain_suffix" in r or "rule_set" in r]
    assert order == ["proxy", "direct", "proxy", "direct"]   # 白名单 → 黑名单 → 学到的 → 规则集
    assert doc["route"]["final"] == "proxy" and doc["route"]["auto_detect_interface"] is True
    dns = doc["dns"]
    assert dns["final"] == "dns-proxy" and "independent_cache" not in dns
    assert all("strategy" not in r for r in dns["rules"])    # 1.14 弃用了 DNS 规则里的 strategy
    assert next(s for s in dns["servers"] if s["tag"] == "dns-proxy")["detour"] == "proxy"
    assert next(s for s in dns["servers"] if s["tag"] == "dns-hosts")["predefined"] == {"h.example": ["192.0.2.1"]}
    # 代理服务器自己的域名必须走国内 DNS 直连解析
    assert {"domain": ["example.test"], "action": "route", "server": "dns-direct"} in dns["rules"]


def test_field_errors(client):
    client.write(extra='[locl]\nport = 1')
    assert "locl" in errs(client) and "local" in errs(client)["locl"]
    client.write(proxy_extra='[proxy.tls]\ncertificate_path = "/nonexistent.crt"')
    assert "proxy.tls.certificate_path" in errs(client)
    client.config.write_text('[proxy]\nprotocol = "trojan"\n')
    assert "proxy.server" in errs(client)


def test_fake_ip_enabled_for_tun(client):
    """fake-ip：只给走代理的域名返回假 IP。

    TUN 下客户端只嗅探不覆盖目标（sing-box 1.13 移除了 sniff_override_destination），
    服务端只能收到 IP；fake-ip 让 sing-box 在出站前用域名替换假 IP，
    等价于恢复旧机制。
    """
    client.write(protocol="hysteria2", proxy_extra='traffic_mode = "tun"', base=False,
                 extra='[dns]\nfake_ip = true\n'
                       '[routing]\nproxy_domains = ["claude.ai", "google.com"]\n'
                       'direct_domains = ["baidu.com"]')
    doc = generate.build(load_config(client.config), PASSWORD)
    fake = next(s for s in doc["dns"]["servers"] if s.get("type") == "fakeip")
    assert fake["tag"] == "dns-fakeip" and fake["inet4_range"] == "198.18.0.0/15"
    # 只对白名单域名启用
    first = doc["dns"]["rules"][0]
    assert first["server"] == "dns-fakeip"
    assert set(first["domain_suffix"]) == {"claude.ai", "google.com"}
    # 直连域名不能走 fake-ip
    assert {"domain_suffix": ["baidu.com"], "action": "route", "server": "dns-direct"} in doc["dns"]["rules"]
    # fake-ip 段的流量要单独嗅探后再按域名分流
    assert {"ip_cidr": ["198.18.0.0/15"], "action": "sniff"} in doc["route"]["rules"]


def test_fake_ip_off_by_default(client):
    client.write(proxy_extra='traffic_mode = "tun"', base=False,
                 extra='[routing]\nproxy_domains = ["claude.ai"]')
    doc = generate.build(load_config(client.config), PASSWORD)
    assert all(s.get("type") != "fakeip" for s in doc["dns"]["servers"])
    assert all("ip_cidr" not in r for r in doc["route"]["rules"])


def test_fake_ip_requires_cache_file(monkeypatch):
    """fake-ip 的「假 IP → 域名」映射靠 experimental.cache_file 持久化。

    不开的话 sing-box 日志会报 `missing fakeip record`，应用拿到假 IP 后直接连不上 ——
    比不开 fake-ip 还糟。这条测试锁住「启用 fake-ip 必须同时启用 cache_file」。
    """
    monkeypatch.setenv("NORAIN_TEST_PW", "pw1234567890")
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        p = d / "cfg.toml"
        p.write_text(
            'schema = 1\n[proxy]\nserver = "47.89.152.13"\ntraffic_mode = "tun"\n'
            'credential_ref = "env:NORAIN_TEST_PW"\n'
            '[proxy.tls]\nserver_name = "www.bing.com"\ninsecure = true\n'
            '[dns]\nfake_ip = true\n[routing]\nproxy_domains = ["claude.ai"]\n',
            encoding="utf-8")
        cfg = load_config(p)
        paths = Paths(home=d, config=p, state=d / "state", log_dir=d / "log",
                      log_dir_from_env=False, singbox=None, platform="nt")
        doc = json.loads(generate.render(cfg, generate.resolve_secret(cfg), paths))
        cache = doc["experimental"]["cache_file"]
        assert cache["enabled"] is True
        # 必须落在状态目录里，否则重启后映射丢失
        assert Path(cache["path"]) == paths.state / "singbox-cache.db"


def test_no_cache_file_without_fake_ip(client):
    """默认不生成 experimental，保持配置最小。"""
    client.write(proxy_extra='traffic_mode = "tun"', base=False,
                 extra='[routing]\nproxy_domains = ["claude.ai"]')
    doc = generate.build(load_config(client.config), PASSWORD)
    assert "experimental" not in doc


def test_fake_ip_ignored_outside_tun(client):
    """mixed / system-proxy 本来就能带域名给服务端，不需要 fake-ip。"""
    client.write(proxy_extra='traffic_mode = "mixed"', base=False,
                 extra='[dns]\nfake_ip = true\n[routing]\nproxy_domains = ["claude.ai"]')
    doc = generate.build(load_config(client.config), PASSWORD)
    assert all(s.get("type") != "fakeip" for s in doc["dns"]["servers"])
    assert "experimental" not in doc


def test_fake_ip_v6_range(client):
    client.write(proxy_extra='traffic_mode = "tun"', base=False,
                 extra='[dns]\nfake_ip = true\nfake_ip_range_v6 = "fc00::/18"\n'
                       '[routing]\nproxy_domains = ["claude.ai"]')
    doc = generate.build(load_config(client.config), PASSWORD)
    fake = next(s for s in doc["dns"]["servers"] if s.get("type") == "fakeip")
    assert fake["inet6_range"] == "fc00::/18"
    assert {"ip_cidr": ["198.18.0.0/15", "fc00::/18"], "action": "sniff"} in doc["route"]["rules"]


@pytest.mark.skipif(os.name == "nt", reason="断言的是 POSIX 路径字符串，Windows 上 Path 会渲染成反斜杠")
def test_paths_per_platform():
    win = Paths.from_env({"APPDATA": r"C:\Users\u\AppData\Roaming",
                          "LOCALAPPDATA": r"C:\Users\u\AppData\Local"}, platform="nt")
    assert "Roaming" in str(win.config) and str(win.config).endswith("cfg.toml")
    assert "Local" in str(win.state) and win.bundled_singbox.name == "sing-box.exe"
    lin = Paths.from_env({"HOME": "/home/u"}, platform="posix")
    assert str(lin.config) == "/home/u/.config/norain/cfg.toml"
    assert str(lin.state) == "/home/u/.local/state/norain" and lin.bundled_singbox.name == "sing-box"
    assert str(Paths.from_env({"HOME": "/h", "NORAIN_CONFIG": "/x/c.toml"}, platform="posix").config) == "/x/c.toml"


@pytest.mark.slow
def test_lifecycle_chain(client):
    r = client.cli("config", "validate", "--json")
    assert r.returncode == 0, r.stdout + r.stderr
    r = client.cli("start")
    assert r.returncode == 0, r.stderr
    assert str(client.port) in r.stdout
    st = client.status()
    assert st["service"]["state"] == "running" and st["process"]["running"] and st["business_code"] == 0
    # status 可能多带 active_protocol 之类的运行时字段，只断言关心的键
    assert {k: st["proxy"][k] for k in ("protocol", "server", "port", "traffic_mode")} == {
        "protocol": "hysteria2", "server": "example.test", "port": 443, "traffic_mode": "mixed"}
    with socket.create_connection(("127.0.0.1", client.port), timeout=3):
        pass
    assert "运行中" in client.cli("status").stdout
    out = client.cli("config", "show").stdout + json.dumps(st) + client.cli("logs").stdout
    assert PASSWORD not in out
    if os.name != "nt":   # Windows 没有 0600 语义
        assert oct((client.state / "run" / "sing-box.json").stat().st_mode & 0o777) == "0o600"

    assert client.cli("stop").returncode == 0
    time.sleep(2.5)
    st = client.status()
    assert st["service"]["state"] == "stopped" and st["desired"] == "stopped"
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", client.port), timeout=1)


@pytest.mark.slow
def test_stop_via_stop_file_only(client):
    """Windows 上不能靠信号干净停止；这里验证只写停止请求文件也能停下来。"""
    assert client.cli("start").returncode == 0
    st = client.status()
    (client.state / "run" / "stop-request").write_text("x")
    end = time.monotonic() + 10
    while time.monotonic() < end and client.status()["service"]["state"] == "running":
        time.sleep(0.2)
    assert client.status()["service"]["state"] == "stopped"
    import psutil
    assert not psutil.pid_exists(st["process"]["pid"])


@pytest.mark.slow
def test_port_conflict_and_restart_limit(client):
    with socket.socket() as s:
        s.bind(("127.0.0.1", client.port))
        s.listen()
        r = client.cli("start", "--json")
        assert json.loads(r.stdout)["business_code"] == 130
    client.write(limit=1)
    assert client.cli("start", env={"FAKE_SB_CRASH": "1"}).returncode != 0
    st = client.status()
    assert st["business_code"] == 160 and st["service"]["state"] == "stopped"
    client.cli("stop")
    assert client.cli("start", env={"FAKE_SB_CRASH_ONCE": str(client.tmp / "once")}).returncode == 0
    assert client.status()["restarts"] == 1


@pytest.mark.slow
def test_restart_with_bad_config_keeps_running(client):
    assert client.cli("start").returncode == 0
    pid = client.status()["process"]["pid"]
    client.write(proxy_extra='traffic_mode = "transparent"')
    assert client.cli("restart").returncode == 3
    assert client.status()["process"]["pid"] == pid
    client.write(protocol="trojan")
    assert client.cli("restart").returncode == 0
    st = client.status()
    assert st["process"]["pid"] != pid and st["proxy"]["protocol"] == "trojan"
