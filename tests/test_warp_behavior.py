"""routing.warp 的 ip_cidr 行为测试：起真实 sing-box，验证按目标 IP 命中 WARP。

背景：客户端 TUN 下服务端只拿到 IP，domain_suffix 匹配不到，流量会落到 final=direct。
ip_cidr 是纯 IP 场景的兜底。

性能：证书和 SOCKS 抓包端在整个模块内复用，只重建 sing-box 进程；
就绪用「端口可连」判断，不盲等。
"""

import datetime
import json
import socket
import threading
import time
from pathlib import Path

import pytest

from norain_server import generate
from norain_server.model import load_config

from harness_singbox import RunningSingBox, check_config, find_singbox, wait_for

SB = find_singbox()

BASE = """
schema = 1
[server]
domain = "example.test"
listen = "127.0.0.1"
[protocols.hysteria2]
enabled = true
port = 8443
[auth]
password = "test-password-1234567890"
[tls]
mode = "self-signed"
"""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    """整个模块复用一张自签证书：生成一次要几十毫秒，没必要每次重做。"""
    tmp = tmp_path_factory.mktemp("warpcert")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=1))
         .sign(key, hashes.SHA256()))
    cf, kf = tmp / "cert.pem", tmp / "key.pem"
    cf.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption()))
    return str(cf), str(kf)


class Catcher:
    """假 SOCKS 出站，记录是否被用到。"""

    def __init__(self):
        self.hits: list[str] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                c.settimeout(3)
                hdr = c.recv(2)
                if len(hdr) < 2:
                    continue
                c.recv(hdr[1])
                c.sendall(b"\x05\x00")
                req = c.recv(4)
                if len(req) >= 4:
                    self.hits.append("connected")
                c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass


def _build(tmp: Path, cert: tuple[str, str], warp_toml: str) -> dict:
    p = tmp / "server.toml"
    p.write_text(BASE + warp_toml, encoding="utf-8")
    cfg = load_config(p, env={})
    return generate.build(cfg, "test-password-1234567890", cert=cert[0], key=cert[1])


# ---- 纯配置断言（不需要 sing-box）----------------------------------------------

def test_ip_cidr_and_domains_go_into_one_rule(tmp_path, cert):
    """domains 和 ip_cidr 必须写进同一条规则，否则会互相覆盖。"""
    doc = _build(tmp_path, cert, """
[routing.warp]
address = "127.0.0.1:40000"
domains = ["claude.ai"]
ip_cidr = ["160.79.104.0/23", "104.18.0.0/16"]
""")
    assert doc["route"]["rules"] == [{
        "domain_suffix": ["claude.ai"],
        "ip_cidr": ["160.79.104.0/23", "104.18.0.0/16"],
        "outbound": "warp",
    }]


def test_warp_outbound_is_socks_to_address(tmp_path, cert):
    doc = _build(tmp_path, cert, """
[routing.warp]
address = "127.0.0.1:40000"
domains = ["claude.ai"]
""")
    assert doc["outbounds"][0] == {"type": "socks", "tag": "warp",
                                   "server": "127.0.0.1", "server_port": 40000}
    assert doc["route"]["final"] == "direct"


# ---- 行为断言（需要真实 sing-box）----------------------------------------------

def _run_connect(tmp_path: Path, cert, target_ip: str, *, expect_hit: bool) -> bool:
    """起 sing-box，连 target_ip，返回 warp 出站是否被命中。

    expect_hit=False 时不能等满超时：没有命中是预期结果，只需要给 sing-box
    一点时间把连接处理完（它会在 direct 出站上立刻失败，不会产生 warp 命中）。
    """
    catcher = Catcher()
    mixed = _free_port()
    try:
        doc = _build(tmp_path, cert, f"""
[routing.warp]
address = "127.0.0.1:{catcher.port}"
domains = ["claude.ai"]
ip_cidr = ["160.79.104.0/23"]
""")
        doc["inbounds"] = [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                            "listen_port": mixed}]
        cp = tmp_path / "c.json"
        cp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        check_config(SB, cp)
        with RunningSingBox(SB, cp, ready_ports=(mixed,)):
            s = socket.create_connection(("127.0.0.1", mixed), timeout=8)
            try:
                s.sendall(f"CONNECT {target_ip}:443 HTTP/1.1\r\nHost: {target_ip}:443\r\n\r\n".encode())
                if expect_hit:
                    wait_for(lambda: bool(catcher.hits), timeout=3)
                else:
                    # 预期不命中：给 sing-box 一点时间走完 direct，再确认确实没命中
                    time.sleep(0.35)
            finally:
                s.close()
        return bool(catcher.hits)
    finally:
        catcher.close()


@pytest.mark.skipif(SB is None, reason="没有可用的真实 sing-box")
def test_ip_cidr_routes_by_target_ip(tmp_path, cert):
    """核心：连接一个落在 ip_cidr 内的目标 IP，必须走 warp 出站。

    这是 TUN 客户端下服务端唯一能用的判据（服务端只拿到 IP）。
    """
    assert _run_connect(tmp_path, cert, "160.79.104.10", expect_hit=True), \
        "落在 ip_cidr 内的目标没有走 warp 出站"


@pytest.mark.skipif(SB is None, reason="没有可用的真实 sing-box")
def test_target_outside_ip_cidr_goes_direct(tmp_path, cert):
    """落在 ip_cidr 外的目标不能走 warp。"""
    assert not _run_connect(tmp_path, cert, "203.0.113.5", expect_hit=False), \
        "ip_cidr 外的目标被错误地送进了 warp"
