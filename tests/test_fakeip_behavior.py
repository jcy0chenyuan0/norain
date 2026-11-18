"""fake_ip 的真实行为测试：起真实 sing-box，验证完整链路。

与 test_client.py 里的配置结构测试互补 —— 那些只检查生成的 JSON 长什么样，
这里验证 sing-box 拿这份配置跑起来以后行为是否正确。

核心链路（TUN 下真实发生的事）：
  1. 应用向 sing-box 查 DNS        -> 走代理的域名拿到假 IP
  2. 应用连接那个假 IP              -> sing-box 反查回域名
  3. 发给服务端的目标是域名          -> 服务端的 domain_suffix 分流才能命中

性能：整个模块共用一个 sing-box 进程，并且用「端口就绪」代替固定 sleep。
所有用例只读不写这个进程的状态，所以共享是安全的。
"""

import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from norain import generate
from norain.model import load_config
from norain.paths import Paths

from harness_singbox import RunningSingBox, check_config, find_singbox, wait_for

SB = find_singbox()
pytestmark = pytest.mark.skipif(SB is None, reason="没有可用的真实 sing-box，跳过行为测试")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Upstream:
    """假上游 DNS：记录被问了什么，返回固定真 IP。"""

    def __init__(self, answers: dict[str, str]):
        self.answers = answers
        self.queried: list[str] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
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
                data, addr = self.sock.recvfrom(512)
            except (socket.timeout, OSError):
                continue
            try:
                self._reply(data, addr)
            except Exception:  # noqa: BLE001
                pass

    def _reply(self, data, addr):
        qid = data[:2]
        i, labels = 12, []
        while i < len(data) and data[i] != 0:
            ln = data[i]
            labels.append(data[i + 1:i + 1 + ln].decode(errors="replace"))
            i += 1 + ln
        i += 1
        qtype = int.from_bytes(data[i:i + 2], "big")
        question = data[12:i + 4]
        self.queried.append(".".join(labels))
        if qtype == 1:
            ip = self.answers.get(".".join(labels), "203.0.113.99")
            ans = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + (60).to_bytes(4, "big")
                   + (4).to_bytes(2, "big") + socket.inet_aton(ip))
            resp = (qid + b"\x81\x80" + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
                    + b"\x00\x00" * 2 + question + ans)
        else:
            resp = (qid + b"\x81\x80" + (0).to_bytes(2, "big") + (0).to_bytes(2, "big")
                    + b"\x00\x00" * 2 + question)
        self.sock.sendto(resp, addr)


class _SocksCatcher:
    """假 SOCKS 出站：记录 sing-box 传过来的目标（域名还是 IP）。"""

    def __init__(self):
        self.targets: list[tuple[str, str]] = []
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
                self._handle(c)
            except Exception:  # noqa: BLE001
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass

    def _handle(self, c):
        c.settimeout(3)
        hdr = c.recv(2)
        if len(hdr) < 2:
            return
        c.recv(hdr[1])
        c.sendall(b"\x05\x00")
        req = c.recv(4)
        if len(req) < 4:
            return
        if req[3] == 1:
            self.targets.append(("IPv4", socket.inet_ntoa(c.recv(4))))
        elif req[3] == 3:
            ln = c.recv(1)[0]
            self.targets.append(("DOMAIN", c.recv(ln).decode(errors="replace")))
        c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")


CFG = """
schema = 1
[proxy]
server = "127.0.0.1"
traffic_mode = "tun"
credential_ref = "env:NORAIN_TEST_PW"
[local]
port = __MIXED__
[proxy.hysteria2]
port = 443
[proxy.tls]
server_name = "www.bing.com"
insecure = true
[dns]
mode = "split"
domestic = "127.0.0.1"
fake_ip = true
fake_ip_range = "198.18.0.0/15"
[routing]
proxy_domains = ["proxy.example"]
direct_domains = ["direct.example"]
"""


class _Env:
    """一个模块内共用的 fake_ip 环境。"""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.dns_in = _free_port()
        self.mixed = _free_port()
        self.upstream = _Upstream({"proxy.example": "203.0.113.11",
                                   "direct.example": "203.0.113.22",
                                   "other.example": "203.0.113.33"})
        self.socks = _SocksCatcher()
        self.singbox: RunningSingBox | None = None
        self._saved_env: str | None = None

    def start(self):
        # 凭证引用要读环境变量；记下原值，stop() 里恢复，别污染后面的测试
        self._saved_env = os.environ.get("NORAIN_TEST_PW")
        os.environ["NORAIN_TEST_PW"] = "pw1234567890"
        cfgp = self.tmp / "cfg.toml"
        cfgp.write_text(CFG.replace("__MIXED__", str(self.mixed)), encoding="utf-8")
        cfg = load_config(cfgp)
        paths = Paths(home=self.tmp, config=cfgp, state=self.tmp / "state",
                      log_dir=self.tmp / "log", log_dir_from_env=False, singbox=None,
                      platform="nt")
        (self.tmp / "state").mkdir(exist_ok=True)
        doc = json.loads(generate.render(cfg, generate.resolve_secret(cfg), paths))

        doc["inbounds"] = [
            {"type": "mixed", "tag": "tun-in", "listen": "127.0.0.1", "listen_port": self.mixed},
            {"type": "direct", "tag": "dns-in", "listen": "127.0.0.1",
             "listen_port": self.dns_in, "override_address": "127.0.0.1", "override_port": 53},
        ]
        doc["outbounds"] = [{"type": "socks", "tag": "proxy", "server": "127.0.0.1",
                             "server_port": self.socks.port}]
        doc["route"].pop("auto_detect_interface", None)
        doc["dns"]["servers"] = [s for s in doc["dns"]["servers"] if s.get("tag") != "dns-proxy"]
        for s in doc["dns"]["servers"]:
            if s.get("tag") == "dns-direct":
                s["server_port"] = self.upstream.port
        for r in doc["dns"]["rules"]:
            if r.get("server") == "dns-proxy":
                r["server"] = "dns-direct"
        if doc["dns"].get("final") == "dns-proxy":
            doc["dns"]["final"] = "dns-direct"
        doc["route"]["default_domain_resolver"] = {"server": "dns-direct"}
        doc.setdefault("log", {})["level"] = "warn"

        cp = self.tmp / "sing-box.json"
        cp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        check_config(SB, cp)
        self.singbox = RunningSingBox(SB, cp, ready_ports=(self.mixed, self.dns_in)).start()
        return self

    def stop(self):
        if self.singbox:
            self.singbox.stop()
        self.upstream.close()
        self.socks.close()
        # 恢复环境变量，避免污染同进程里后续的测试
        if self._saved_env is None:
            os.environ.pop("NORAIN_TEST_PW", None)
        else:
            os.environ["NORAIN_TEST_PW"] = self._saved_env

    def restart(self):
        """只重启 sing-box 进程，配置文件与 cache_file 都沿用。

        用来验证 cache_file 是否真的把「假 IP -> 域名」映射持久化了。
        """
        assert self.singbox is not None
        self.singbox.stop()
        cp = self.tmp / "sing-box.json"
        self.singbox = RunningSingBox(SB, cp, ready_ports=(self.mixed, self.dns_in)).start()

    def resolve(self, name: str) -> str | None:
        pkt = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for part in name.split("."):
            pkt += bytes([len(part)]) + part.encode()
        pkt += b"\x00\x00\x01\x00\x01"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4)
        try:
            s.sendto(pkt, ("127.0.0.1", self.dns_in))
            data, _ = s.recvfrom(512)
        except (socket.timeout, OSError):
            return None
        finally:
            s.close()
        i = 12
        while i < len(data) and data[i] != 0:
            i += 1 + data[i]
        i += 5
        for _ in range(int.from_bytes(data[6:8], "big")):
            if data[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while i < len(data) and data[i] != 0:
                    i += 1 + data[i]
                i += 1
            rtype = int.from_bytes(data[i:i + 2], "big")
            rdlen = int.from_bytes(data[i + 8:i + 10], "big")
            rdata = data[i + 10:i + 10 + rdlen]
            i += 10 + rdlen
            if rtype == 1 and len(rdata) == 4:
                return socket.inet_ntoa(rdata)
        return None

    def connect_ip(self, ip: str, port: int = 443) -> list[tuple[str, str]]:
        before = len(self.socks.targets)
        failure: str | None = None
        try:
            s = socket.create_connection(("127.0.0.1", self.mixed), timeout=8)
            try:
                s.sendall(f"CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n".encode())
                # 等 socks 抓到目标，而不是先睡再轮询
                wait_for(lambda: len(self.socks.targets) > before, timeout=3)
            finally:
                s.close()
        except OSError as e:
            failure = f"{type(e).__name__}: {e}"
        got = self.socks.targets[before:]
        if not got and failure:
            # 没抓到又没报错才是最可疑的情况，把真实原因带出来便于排查
            raise AssertionError(f"连接 {ip} 失败，且 socks 没有记录到目标: {failure}")
        return got


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fakeip")
    e = _Env(tmp).start()
    yield e
    e.stop()


# ---- 行为测试 -------------------------------------------------------------------

def test_fake_ip_returns_fake_address_for_proxy_domains(env):
    """走代理的域名必须拿到假 IP，这样服务端才能反查回域名。"""
    assert env.resolve("proxy.example") == "198.18.0.2"


def test_fake_ip_does_not_pollute_direct_domains(env):
    """直连域名必须拿真 IP：给了假 IP 应用就连不上，也会破坏直连判定。"""
    assert env.resolve("direct.example") == "203.0.113.22"


def test_fake_ip_lets_server_see_the_domain(env):
    """核心：连接假 IP 时，出站必须还原成域名。

    这是 fake_ip 存在的全部意义 —— TUN 下服务端只拿到 IP，domain_suffix 分流会失效，
    还原成域名后服务端才能按域名命中 WARP 等规则。
    """
    fake = env.resolve("proxy.example")
    assert fake and fake.startswith("198.18."), f"没拿到假 IP: {fake}"
    targets = env.connect_ip(fake)
    assert targets == [("DOMAIN", "proxy.example")], f"出站没还原成域名: {targets}"


def test_fake_ip_mapping_survives_restart(tmp_path):
    """重启 sing-box 后，假 IP 与域名的对应关系仍然可用。

    注意这条测试的边界：它证明「重启后可用」，但**不能**证明 cache_file 是必需的。
    实测（sing-box 1.14.4）带不带 cache_file 行为一致 —— 重启后重新解析都会拿到同一个
    假 IP，连它也都能还原。cache_file 的价值在于让映射跨重启保持稳定、避免应用钉住
    旧假 IP 时连不上，属于优化而非硬性前提。
    """
    e = _Env(tmp_path).start()
    try:
        fake = e.resolve("proxy.example")
        assert fake and fake.startswith("198.18."), f"第一阶段没拿到假 IP: {fake}"
        assert e.connect_ip(fake) == [("DOMAIN", "proxy.example")], "重启前就无法还原，环境有问题"

        e.restart()

        again = e.resolve("proxy.example")
        assert again == fake, f"重启后假 IP 变了（{fake} -> {again}）"

        # 载入映射之后，原来那个假 IP 也能还原
        assert e.connect_ip(fake) == [("DOMAIN", "proxy.example")], \
            "重启后假 IP 没能还原成域名"
    finally:
        e.stop()


def test_fake_ip_skips_upstream_for_faked_domains(env):
    """假 IP 域名不应该去问上游 DNS（问了就说明 fakeip 规则没命中）。

    断言「某件事没有发生」天然容易假阳性：上游线程可能只是慢了一拍。
    所以先等一个「确实问了上游」的对照（direct.example），确认上游记录链路是通的，
    再断言 proxy.example 这条链路上确实没有记录。
    """
    env.resolve("direct.example")
    assert wait_for(lambda: "direct.example" in env.upstream.queried), \
        "上游 DNS 完全没有收到查询，这个断言不可信（记录链路本身有问题）"

    before = len(env.upstream.queried)
    env.resolve("proxy.example")
    # 给上游一点时间：如果它真的被问了，这段时间足够记录下来
    time.sleep(0.3)
    assert "proxy.example" not in env.upstream.queried[before:], \
        f"fakeip 域名被错误地转发给了上游: {env.upstream.queried[before:]}"


def test_real_ip_is_not_reverse_mapped(env):
    """对照组：直接连真实 IP 时，出站保持 IP、不会凭空还原成域名。

    只有假 IP 才会被反查回域名，这条防止「还原成域名」的测试因为别的原因虚假通过。
    """
    targets = env.connect_ip("203.0.113.11")
    assert targets == [("IPv4", "203.0.113.11")], f"真实 IP 被意外还原: {targets}"
