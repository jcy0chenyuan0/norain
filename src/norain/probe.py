"""探测工具：监控模块、分流模块和自适应选协议共用。

「走代理」和「直连」都通过 sing-box 的本地入口（HTTP 代理）发出：
  - 走 mixed-in：经过完整的分流规则，等同于用户的真实流量；
  - 走 probe-direct / probe-<协议>：绕过分流，强制直连或强制走某个协议。
这样 TUN 模式下探测流量不会被自己接管。没有可用入口时（代理没在运行）才用裸连接。
"""

from __future__ import annotations

import functools
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

Proxy = tuple[str, int] | None

_UA = "Mozilla/5.0 (norain-probe)"


@dataclass
class Result:
    ok: bool
    target: str = ""
    via: str = ""
    status: int | None = None
    elapsed_ms: float | None = None
    error: str = ""
    body: str = field(default="", repr=False)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "target": self.target, "via": self.via, "status": self.status,
                "elapsed_ms": round(self.elapsed_ms, 1) if self.elapsed_ms is not None else None,
                "error": self.error}


@functools.lru_cache(maxsize=2)
def _ssl_context(verify: bool) -> ssl.SSLContext:
    """TLS 上下文只建两个（校验 / 不校验）并复用。

    create_default_context() 每次都要加载系统的整个 CA 证书库（Windows 上要枚举证书存储），
    而监控每一轮有十来个探测、每个探测都新建一次——这是探测路径上最大的一笔固定开销。
    SSLContext 可以在线程间共享。
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


@functools.lru_cache(maxsize=32)
def _opener(proxy: Proxy, verify: bool) -> urllib.request.OpenerDirector:
    """按（本地入口, 是否校验证书）缓存 opener：入口只有固定的几个，opener 不带连接状态。"""
    handlers: list = [urllib.request.HTTPSHandler(context=_ssl_context(verify))]
    if proxy:
        addr = f"http://{proxy[0]}:{proxy[1]}"
        handlers.append(urllib.request.ProxyHandler({"http": addr, "https": addr}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))  # 明确忽略系统代理和环境变量
    return urllib.request.build_opener(*handlers)


def http(url: str, *, proxy: Proxy = None, timeout: float = 5.0, via: str = "", method: str = "GET",
         headers: dict | None = None, max_bytes: int = 8192, verify: bool = True) -> Result:
    """发一个 HTTP 请求。任何 HTTP 状态码（包括 4xx/5xx）都算「连通」，只有网络层失败才算不通。"""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": _UA, **(headers or {})})
    started = time.monotonic()
    try:
        with _opener(tuple(proxy) if proxy else None, verify).open(req, timeout=timeout) as r:
            body = r.read(max_bytes).decode("utf-8", "replace")
            return Result(True, url, via, r.status, (time.monotonic() - started) * 1000, body=body)
    except urllib.error.HTTPError as e:
        return Result(True, url, via, e.code, (time.monotonic() - started) * 1000)
    except (urllib.error.URLError, OSError, ValueError, ssl.SSLError) as e:
        reason = getattr(e, "reason", e)
        return Result(False, url, via, None, None, error=str(reason)[:200])


def trace(url: str, *, proxy: Proxy = None, timeout: float = 5.0, via: str = "") -> dict | None:
    """查询出口 IP 和位置（Cloudflare /cdn-cgi/trace 格式：每行 key=value）。无返回时为 None。"""
    # 校验证书：伪造的出口位置会掩盖泄漏。默认的 1.1.1.1 / 2606:4700:4700::1111 证书带 IP SAN
    r = http(url, proxy=proxy, timeout=timeout, via=via)
    if not r.ok or r.status != 200:
        return None
    kv = dict(line.split("=", 1) for line in r.body.splitlines() if "=" in line)
    if "ip" not in kv:
        return None
    return {"ip": kv["ip"], "loc": kv.get("loc", "").upper(), "via": via}


def reachable(host: str, *, proxy: Proxy = None, timeout: float = 5.0, via: str = "") -> Result:
    """某个域名能不能访问：先试 HTTPS，再试 HTTP。
    这里不校验证书：结果只是一个「连得上 / 连不上」的布尔值，不读取也不信任任何响应内容。"""
    r = http(f"https://{host}/", proxy=proxy, timeout=timeout, via=via, method="HEAD", verify=False)
    if r.ok:
        return r
    r2 = http(f"http://{host}/", proxy=proxy, timeout=timeout, via=via, method="HEAD")
    return r2 if r2.ok else r


def tcp(host: str, port: int, *, proxy: Proxy = None, timeout: float = 5.0) -> bool:
    """TCP 连通性。经代理时用 HTTP CONNECT，并在隧道里做一次 TLS 握手确认对端真的可达。"""
    try:
        if proxy is None:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        with socket.create_connection(proxy, timeout=timeout) as s:
            target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            head = s.recv(4096)
            if b" 200" not in head.split(b"\r\n", 1)[0]:
                return False
            if port != 443:
                return True
            with _ssl_context(False).wrap_socket(s, server_hostname=None):
                return True
    except (OSError, ssl.SSLError):
        return False


def doh(endpoint: str, name: str, *, proxy: Proxy = None, timeout: float = 5.0) -> list[str]:
    """用 JSON 接口查询 A 和 AAAA 记录（阿里 /resolve、Cloudflare/Google /dns-query 都支持）。"""
    ips: list[str] = []
    for rtype, code in (("A", 1), ("AAAA", 28)):
        q = urllib.parse.urlencode({"name": name, "type": rtype})
        sep = "&" if "?" in endpoint else "?"
        r = http(f"{endpoint}{sep}{q}", proxy=proxy, timeout=timeout,
                 headers={"Accept": "application/dns-json"}, max_bytes=65536)  # 校验证书，防止解析结果被篡改
        if not r.ok or r.status != 200:
            continue
        try:
            answers = json.loads(r.body).get("Answer") or []
        except ValueError:
            continue
        ips += [a["data"] for a in answers if a.get("type") == code and a.get("data")]
    return ips


def system_resolve(name: str) -> list[str]:
    """用系统解析器解析（TUN 模式下会被 sing-box 接管，等同于应用看到的结果）。"""
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(name, None)})
    except OSError:
        return []


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False
