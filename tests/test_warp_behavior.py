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
    """域名与目标 IP 属于同一匹配组，命中任意一项即可。"""
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

class LoopbackListener:
    """一个真实的回环监听器，用来证明「直连真的把连接送达了」。

    只用「warp 出站没被命中」来断言直连是不够的：连接被拒绝、超时、静默失败时
    同样不会命中 warp，测试会假阳性。这里放一个真的服务，要求连接确实到达。
    """

    def __init__(self, host: str = "127.0.0.1"):
        self.hits = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
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
            self.hits += 1
            try:
                c.close()
            except OSError:
                pass


def _warp_doc(tmp_path: Path, cert, warp_port: int, cidr: str) -> dict:
    doc = _build(tmp_path, cert, f"""
[routing.warp]
address = "127.0.0.1:{warp_port}"
domains = ["claude.ai"]
ip_cidr = ["{cidr}"]
""")
    return doc


# 命中用例把「网段和目标」一起换成回环地址：即使分流逻辑回归成 direct，测试进程也只是
# 连本机，不会真的去连公网 IP，断言内容完全相同。
# 只取 127.0.0.1/32 而不是整个 127/8，好让直连用例有明确落在网段外的回环目标。
HIT_CIDR = "127.0.0.1/32"
HIT_TARGET = "127.0.0.1"
OUTSIDE_TARGET = "127.0.0.2"   # 同为回环，但不在 HIT_CIDR 内

@pytest.mark.skipif(SB is None, reason="没有可用的真实 sing-box")
def test_ip_cidr_routes_by_target_ip(tmp_path, cert):
    """核心：连接一个落在 ip_cidr 内的目标 IP，必须走 warp 出站。

    这是 TUN 客户端下服务端唯一能用的判据（服务端只拿到 IP）。
    """
    catcher = Catcher()
    mixed = _free_port()
    try:
        doc = _warp_doc(tmp_path, cert, catcher.port, HIT_CIDR)
        doc["inbounds"] = [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                            "listen_port": mixed}]
        cp = tmp_path / "c.json"
        cp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        check_config(SB, cp)
        with RunningSingBox(SB, cp, ready_ports=(mixed,)):
            s = socket.create_connection(("127.0.0.1", mixed), timeout=8)
            try:
                s.sendall(f"CONNECT {HIT_TARGET}:443 HTTP/1.1\r\n"
                          f"Host: {HIT_TARGET}:443\r\n\r\n".encode())
                wait_for(lambda: bool(catcher.hits), timeout=3)
            finally:
                s.close()
        assert catcher.hits, "落在 ip_cidr 内的目标没有走 warp 出站"
    finally:
        catcher.close()


@pytest.mark.skipif(SB is None, reason="没有可用的真实 sing-box")
def test_target_outside_ip_cidr_goes_direct(tmp_path, cert):
    """落在 ip_cidr 外的目标必须直连成功，且不走 warp。

    目标用真实的回环监听器：既证明没被错误地送进 warp，也证明直连确实送达了
    （连接被拒绝或超时同样不会命中 warp，单看这一点会假阳性）。
    """
    catcher = Catcher()
    target = LoopbackListener(OUTSIDE_TARGET)
    mixed = _free_port()
    try:
        doc = _warp_doc(tmp_path, cert, catcher.port, HIT_CIDR)
        doc["inbounds"] = [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                            "listen_port": mixed}]
        cp = tmp_path / "c.json"
        cp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        check_config(SB, cp)
        with RunningSingBox(SB, cp, ready_ports=(mixed,)):
            s = socket.create_connection(("127.0.0.1", mixed), timeout=8)
            try:
                s.sendall(f"CONNECT {OUTSIDE_TARGET}:{target.port} HTTP/1.1\r\n"
                          f"Host: {OUTSIDE_TARGET}:{target.port}\r\n\r\n".encode())
                # 直连应当真的把连接送到回环监听器
                wait_for(lambda: target.hits > 0, timeout=3)
            finally:
                s.close()
        assert not catcher.hits, "ip_cidr 外的目标被错误地送进了 warp"
        assert target.hits > 0, "直连没有把连接送达回环监听器（可能被拒绝或超时）"
    finally:
        catcher.close()
        target.close()
