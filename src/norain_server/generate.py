"""server.toml → sing-box JSON，以及「生成 → check → 备份 → 原子替换」流程。"""

from __future__ import annotations

from pathlib import Path

from norain_core import apply as core_apply
from norain_core.secrets import Secret, resolve

from .model import SCHEMA_VERSION, ServerConfig
from .paths import Paths

USER_NAME = "norain"
ACME_TAG = "norain-acme"


def resolve_secret(cfg: ServerConfig) -> Secret:
    if cfg.auth.password:
        return Secret(value=cfg.auth.password, source="config:auth.password")
    return resolve(cfg.auth.credential_ref)


def cert_paths(cfg: ServerConfig, paths: Paths) -> tuple[Path, Path]:
    """manual / self-signed 的证书和私钥路径。acme 模式没有固定文件，返回值不会被使用。"""
    if cfg.tls.mode == "acme":
        return paths.acme_dir / "acme.crt", paths.acme_dir / "acme.key"
    if cfg.tls.mode == "self-signed" and not (cfg.tls.certificate and cfg.tls.private_key):
        return paths.tls_dir / "self-signed.crt", paths.tls_dir / "self-signed.key"
    return Path(cfg.tls.certificate).expanduser(), Path(cfg.tls.private_key).expanduser()


def acme_provider(cfg: ServerConfig, acme_dir: Path) -> dict:
    """sing-box 1.14 的顶层 certificate_providers 条目（不使用已弃用的 TLS 内联 acme）。

    挑战方式：默认 HTTP-01（需要 80/tcp 可从公网访问）。TLS-ALPN-01 需要 443/tcp 上的 TLS
    监听，只有 Trojan 正好监听 443/tcp 时才保留，其余情况显式关闭。
    """
    tj = cfg.protocols.trojan
    prov: dict = {"type": "acme", "tag": ACME_TAG, "domain": [cfg.server.domain],
                  "data_directory": str(acme_dir),
                  "disable_tls_alpn_challenge": not (tj.enabled and tj.port == 443)}
    if cfg.tls.email:
        prov["email"] = cfg.tls.email
    if cfg.tls.acme_provider:
        prov["provider"] = cfg.tls.acme_provider
    return prov


def build(cfg: ServerConfig, password: str, cert: Path, key: Path, *,
          acme_dir: Path | None = None) -> dict:
    """生成 sing-box 1.14 配置。已用真实 sing-box 1.14.4 check 验证 5 种组合。"""
    acme = cfg.tls.mode == "acme"

    def tls(**extra) -> dict:
        if acme:
            return {"enabled": True, "server_name": cfg.server.domain,
                    "certificate_provider": ACME_TAG, **extra}
        return {"enabled": True, "server_name": cfg.server.domain,
                "certificate_path": str(cert), "key_path": str(key), **extra}

    users = [{"name": USER_NAME, "password": password}]
    inbounds = []
    if cfg.protocols.hysteria2.enabled:
        inbounds.append({
            "type": "hysteria2", "tag": "hy2-in",
            "listen": cfg.server.listen, "listen_port": cfg.protocols.hysteria2.port,
            "users": users, "tls": tls(alpn=["h3"]),
        })
    if cfg.protocols.trojan.enabled:
        inbound = {
            "type": "trojan", "tag": "trojan-in",
            "listen": cfg.server.listen, "listen_port": cfg.protocols.trojan.port,
            "users": users, "tls": tls(),
        }
        fb = cfg.protocols.trojan.fallback
        if fb:
            inbound["fallback"] = {"server": fb.host, "server_port": fb.port}
        inbounds.append(inbound)
    outbounds: list[dict] = [{"type": "direct", "tag": "direct"}]
    route_rules: list[dict] = []
    warp = cfg.routing.warp
    if warp is not None and (warp.domains or warp.ip_cidr):
        # 与原来的服务端一致：这些域名/网段从本机 WARP 出去，其余直连。
        # 域名规则先匹配（客户端走 mixed 入站时目标就是域名）；
        # ip_cidr 是 TUN 场景的兜底——sing-box 1.13+ 去掉了 sniff_override_destination，
        # 客户端只嗅探不覆盖，服务端收到的目标仍是 IP，只能按 IP 段命中。
        host, _, port = warp.address.rpartition(":")
        outbounds.insert(0, {"type": "socks", "tag": "warp", "server": host, "server_port": int(port)})
        rule: dict = {}
        if warp.domains:
            rule["domain_suffix"] = [d.strip().lower() for d in warp.domains]
        if warp.ip_cidr:
            rule["ip_cidr"] = [c.strip() for c in warp.ip_cidr]
        rule["outbound"] = "warp"
        route_rules.append(rule)
    doc: dict = {
        "log": {"level": cfg.logging.level, "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"final": "direct", **({"rules": route_rules} if route_rules else {})},
    }
    if acme:
        doc["certificate_providers"] = [acme_provider(cfg, acme_dir or Path("acme"))]
    return doc


dumps, version_of, ApplyResult = core_apply.dumps, core_apply.version_of, core_apply.ApplyResult


def render(cfg: ServerConfig, secret: Secret, paths: Paths) -> bytes:
    cert, key = cert_paths(cfg, paths)
    return dumps(build(cfg, secret.value, cert, key, acme_dir=paths.acme_dir))


def apply(cfg: ServerConfig, secret: Secret, paths: Paths, binary: Path) -> ApplyResult:
    """生成候选配置并用 sing-box check 校验，通过后才替换当前配置。"""
    return core_apply.apply(render(cfg, secret, paths), run_dir=paths.run_dir,
                            current=paths.current_json, backups=paths.backups,
                            meta=paths.meta_json, source=paths.config, schema=SCHEMA_VERSION,
                            binary=binary)
