"""证书检查和自签证书生成。规则见 docs/decisions/0015。"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from norain_core.errors import BIZ_CERT, EXIT_CONFIG, EXIT_CONFLICT, FieldError, NorainError

WARN_DAYS = 14


@dataclass
class CertStatus:
    certificate: str
    private_key: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    not_after: str | None = None
    days_left: int | None = None
    fingerprint_sha256: str | None = None
    self_signed: bool | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict:
        return {"ok": self.ok, **self.__dict__}

    def raise_if_invalid(self) -> None:
        if self.errors:
            raise NorainError(
                "证书无效", exit_code=EXIT_CONFIG, business_code=BIZ_CERT, module="cert",
                field_errors=[FieldError("tls", e) for e in self.errors],
                hint="manual 模式检查证书路径；自用可运行 cert self-signed --domain <域名>")


def _matches(domain: str, cert: x509.Certificate) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    try:
        ip = ipaddress.ip_address(domain)
        return ip in san.get_values_for_type(x509.IPAddress)
    except ValueError:
        pass
    domain = domain.lower().rstrip(".")
    for name in san.get_values_for_type(x509.DNSName):
        name = name.lower().rstrip(".")
        if name == domain:
            return True
        if name.startswith("*.") and "." in domain and domain.split(".", 1)[1] == name[2:]:
            return True
    return False


def check(cert_path: Path, key_path: Path, domain: str, *, now: dt.datetime | None = None) -> CertStatus:
    st = CertStatus(str(cert_path), str(key_path))
    now = now or dt.datetime.now(dt.timezone.utc)
    cert = key = None
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except FileNotFoundError:
        st.errors.append(f"证书文件不存在：{cert_path}")
    except PermissionError:
        st.errors.append(f"无权读取证书文件：{cert_path}")
    except ValueError:
        st.errors.append(f"证书文件不是有效的 PEM 证书：{cert_path}")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if os.name == "posix" and key_path.stat().st_mode & 0o077:
            st.warnings.append(f"私钥文件权限过宽：{key_path}，建议 chmod 600")
    except FileNotFoundError:
        st.errors.append(f"私钥文件不存在：{key_path}")
    except PermissionError:
        st.errors.append(f"无权读取私钥文件：{key_path}")
    except (ValueError, TypeError):
        st.errors.append(f"私钥文件不是有效的未加密 PEM 私钥：{key_path}")
    if cert is None:
        return st

    st.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
    st.self_signed = cert.issuer == cert.subject
    st.not_after = cert.not_valid_after_utc.isoformat()
    st.days_left = (cert.not_valid_after_utc - now).days
    if now < cert.not_valid_before_utc:
        st.errors.append("证书尚未生效")
    if now >= cert.not_valid_after_utc:
        st.errors.append(f"证书已过期（{st.not_after}）")
    elif st.days_left < WARN_DAYS:
        st.warnings.append(f"证书将在 {st.days_left} 天后过期")
    if not _matches(domain, cert):
        st.errors.append(f"证书的 SAN 不包含 {domain}")
    if key is not None:
        pub = lambda k: k.public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
        if pub(cert.public_key()) != pub(key.public_key()):
            st.errors.append("证书与私钥不匹配")
    if st.self_signed:
        st.warnings.append("自签证书，仅限自用；客户端需要显式信任这张证书")
    return st


def _san(domain: str) -> str:
    try:
        ipaddress.ip_address(domain)
        return f"IP:{domain}"
    except ValueError:
        return f"DNS:{domain}"


def _generate_openssl(domain: str, cert_path: Path, key_path: Path, days: int) -> bool:
    exe = shutil.which("openssl")
    if not exe:
        return False
    proc = subprocess.run(
        [exe, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-days", str(days), "-subj", f"/CN={domain}", "-addext", f"subjectAltName={_san(domain)}",
         "-keyout", str(key_path), "-out", str(cert_path)],
        capture_output=True, text=True, timeout=30)
    return proc.returncode == 0


def _generate_python(domain: str, cert_path: Path, key_path: Path, days: int) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    try:
        alt: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(domain))
    except ValueError:
        alt = x509.DNSName(domain)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
            .sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def self_signed(domain: str, cert_path: Path, key_path: Path, *, days: int = 365,
                force: bool = False) -> tuple[CertStatus, str]:
    """生成自签证书。优先用 openssl（最初目标），没有时用 cryptography。返回（状态，生成方式）。"""
    if not domain.strip():
        raise NorainError("--domain 不能为空", exit_code=2, module="cert")
    if (cert_path.exists() or key_path.exists()) and not force:
        raise NorainError(f"{cert_path} 或 {key_path} 已存在。确认要覆盖时加 --force",
                          exit_code=EXIT_CONFLICT, module="cert")
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(cert_path.parent, 0o700)
    if force:  # 先清掉旧文件，避免 openssl 失败时留下新旧混杂的一对
        cert_path.unlink(missing_ok=True)
        key_path.unlink(missing_ok=True)
    old_umask = os.umask(0o077)
    try:
        method = "openssl"
        if not _generate_openssl(domain, cert_path, key_path, days):
            method = "cryptography"
            _generate_python(domain, cert_path, key_path, days)
    finally:
        os.umask(old_umask)
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)
    return check(cert_path, key_path, domain), method


# ---- acme ----------------------------------------------------------------------

def _port80_busy() -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if os.name == "posix":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", 80))
        except PermissionError:
            return False  # 没有权限探测，不下结论
        except OSError:
            return True
    return False


def acme_status(domain: str, acme_dir: Path, *, tags: frozenset[str] | None = None,
                service_running: bool = False, now: dt.datetime | None = None) -> CertStatus:
    """acme 模式的检查。证书由 sing-box 内置 ACME 申请和续期，Norain 只检查前置条件；
    在数据目录里找到已签发的证书时报告有效期。"""
    st = CertStatus("(acme)", "(acme)")
    now = now or dt.datetime.now(dt.timezone.utc)
    if not domain.strip():
        st.errors.append("acme 模式需要域名（server.domain）")
    if tags is not None and "with_acme" not in tags:
        st.errors.append("当前 sing-box 不带 with_acme 构建标签，无法使用 acme 模式")
    if not service_running and _port80_busy():
        st.warnings.append("80/tcp 已被其他程序占用，HTTP-01 挑战可能失败"
                           "（让 Trojan 监听 443/tcp 可改走 TLS-ALPN-01）")
    issued = None
    try:
        for f in acme_dir.rglob("*.crt"):
            if f.stem == domain:
                issued = f
                break
    except OSError:
        pass
    if issued is None:
        st.warnings.append("还没有签发的证书：首次启动后 sing-box 会自动申请，需要 80/tcp 可从公网访问")
        return st
    try:
        cert = x509.load_pem_x509_certificate(issued.read_bytes())
    except (OSError, ValueError):
        st.warnings.append(f"无法读取已签发的证书：{issued}")
        return st
    st.certificate = str(issued)
    st.self_signed = False
    st.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
    st.not_after = cert.not_valid_after_utc.isoformat()
    st.days_left = (cert.not_valid_after_utc - now).days
    if now >= cert.not_valid_after_utc:
        st.errors.append(f"ACME 证书已过期（{st.not_after}），续期失败，检查 80/tcp 和域名解析")
    elif st.days_left < WARN_DAYS:
        st.warnings.append(f"ACME 证书将在 {st.days_left} 天后过期，自动续期可能没有成功")
    return st
