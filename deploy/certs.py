"""内置 CA：局域网部署不用自己准备证书。

`ces setup` 选"给局域网用、自动生成证书"时：
- 在 <数据目录>/tls/ 生成本服务专用的 CA（ca.pem / ca.key，私钥 0600），十年有效；
- 用它签发服务器证书（server.pem / server.key），证书里写上本机的主机名与各网卡地址，两年有效；
- 服务端在 GET /ca.pem 公开 CA 证书（证书本身不是机密），管理菜单显示"连接串"：
  https://<地址>:<端口>#ca=<CA 证书的 SHA-256 指纹>。客户端下载 CA 证书后先核对指纹，再拿它校验
  服务器证书；下载途中被调包，指纹对不上，客户端拒绝。
- 网关（跳板机）的证书也由同一个 CA 签发（`ces tls gateway`），客户端、网关、服务端只认这一份 CA。

依赖 cryptography（随安装包打入），不依赖机器上的 openssl。
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

CA_DAYS = 3650
LEAF_DAYS = 825
RENEW_BEFORE_DAYS = 30


class CertError(RuntimeError):
    pass


def tls_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "tls"


def ca_paths(data_dir: Path) -> tuple[Path, Path]:
    root = tls_dir(data_dir)
    return root / "ca.pem", root / "ca.key"


def server_paths(data_dir: Path) -> tuple[Path, Path]:
    root = tls_dir(data_dir)
    return root / "server.pem", root / "server.key"


def _crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:  # 源码安装没装依赖
        raise CertError("缺少 cryptography 库，无法生成证书：pip install cryptography") from None
    return x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID


def _write_private(path: Path, data: bytes, mode: int, *, private_dir: bool = False) -> None:
    """原子写入；private_dir 时把所在目录设为 700（只用于数据目录里的 tls/，别人的输出目录不动）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    if private_dir:
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def fingerprint(cert_path: Path) -> str:
    """证书 DER 编码的 SHA-256，64 位小写十六进制（连接串里 #ca= 后面就是它）。"""
    pem = Path(cert_path).read_text(encoding="ascii")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def pretty_fingerprint(value: str) -> str:
    """给人核对用：每 4 位一组。"""
    return " ".join(value[i:i + 4] for i in range(0, len(value), 4)).upper()


def ensure_ca(data_dir: Path) -> Path:
    """没有就生成；已有就原样用（换 CA 会让所有客户端都要重新核对指纹，不自动换）。"""
    cert_path, key_path = ca_paths(data_dir)
    if cert_path.is_file() and key_path.is_file():
        return cert_path
    if cert_path.exists() or key_path.exists():
        missing = key_path if cert_path.exists() else cert_path
        raise CertError(f"内置 CA 不完整：缺少 {missing}。不会自动换一个新的 CA（那样所有用户都要重新初始化）；"
                        "把它放回去，或者确实要换 CA 时删掉整个 tls 目录再运行 ces setup")
    x509, hashes, serialization, ec, _, NameOID = _crypto()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "compile-excel-server"),
        x509.NameAttribute(NameOID.COMMON_NAME,
                           f"compile-excel-server CA ({socket.gethostname()[:40]})"),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    _write_private(key_path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), 0o600, private_dir=True)
    _write_private(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644,
                   private_dir=True)
    return cert_path


_HOST_LABEL = re.compile(r"^[A-Za-z0-9-]{1,63}$")


def _split_names(names: list[str]) -> tuple[list[str], list[str]]:
    dns, ips = [], []
    for raw in names:
        name = (raw or "").strip().strip("[]")
        if not name:
            continue
        try:
            ips.append(str(ipaddress.ip_address(name)))
        except ValueError:
            if len(name) > 253 or not all(_HOST_LABEL.match(part) for part in name.split(".")):
                raise CertError(f"不是合法的主机名或 IP 地址：{name!r}（主机名只能用英文字母、数字和 -）"
                                ) from None
            dns.append(name.lower())
    return sorted(set(dns)), sorted(set(ips), key=lambda ip: ipaddress.ip_address(ip).packed)


def issue(data_dir: Path, names: list[str], cert_path: Path, key_path: Path,
          *, common_name: str = "", private_dir: bool = False) -> Path:
    """用内置 CA 签发一张服务器证书（服务端自己、或跳板机上的网关）。"""
    x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID = _crypto()
    dns, ips = _split_names(names)
    if not dns and not ips:
        raise CertError("证书里至少要有一个主机名或 IP 地址")
    ca_cert_path, ca_key_path = ca_paths(data_dir)
    ensure_ca(data_dir)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    alt = [x509.DNSName(name) for name in dns] + [
        x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(
                NameOID.COMMON_NAME, (common_name or (dns + ips)[0])[:64])]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=LEAF_DAYS))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write_private(Path(key_path), key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), 0o600, private_dir=private_dir)
    _write_private(Path(cert_path), cert.public_bytes(serialization.Encoding.PEM), 0o644,
                   private_dir=private_dir)
    return Path(cert_path)


def cert_info(cert_path: Path) -> dict:
    """证书里写了哪些地址、何时到期、由谁签发。"""
    x509, *_ = _crypto()
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    try:
        alt = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in alt.get_values_for_type(x509.DNSName)] + [
            str(v) for v in alt.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    expires = cert.not_valid_after_utc
    return {"names": names, "expires": expires.strftime("%Y-%m-%d"),
            "days_left": (expires - dt.datetime.now(dt.timezone.utc)).days,
            "issuer": cert.issuer.rfc4514_string()}


def interface_addresses() -> list[str]:
    """本机各网卡的 IPv4 / IPv6 地址（不含回环与链路本地）。标准库没有枚举网卡的接口：
    Linux 用 ip，macOS 用 ifconfig；都没有时退回主机名解析。"""
    found: set[str] = set()
    for argv in (["ip", "-o", "addr", "show"], ["ifconfig"]):
        if shutil.which(argv[0]) is None:
            continue
        try:
            text = subprocess.run(argv, capture_output=True, text=True, timeout=5,
                                  check=False).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for match in re.finditer(r"\binet6?\s+(?:addr:)?([0-9A-Fa-f:.]+)", text):
            found.add(match.group(1))
        if found:
            break
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(str(info[4][0]))
    except OSError:
        pass
    usable = []
    for raw in found:
        try:
            addr = ipaddress.ip_address(raw.split("%")[0])
        except ValueError:
            continue
        if not (addr.is_loopback or addr.is_link_local or addr.is_unspecified):
            usable.append(str(addr))
    return sorted(set(usable), key=lambda a: (ipaddress.ip_address(a).version,
                                             ipaddress.ip_address(a).packed))


def default_route_ip() -> str:
    """有默认路由时，对外的那块网卡的 IPv4；没有返回空串。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))  # 不真发包，只为让系统选出对外的网卡地址
            return sock.getsockname()[0]
    except OSError:
        return ""


def local_names(host: str = "") -> list[str]:
    """服务器证书默认写进哪些地址：本机主机名、全部网卡地址、回环；绑定了具体地址就加上它。"""
    names = {"localhost", "127.0.0.1", socket.gethostname(), *interface_addresses()}
    try:
        fqdn = socket.getfqdn()
        if fqdn and "." in fqdn and not fqdn.endswith(".arpa"):
            names.add(fqdn)
    except OSError:
        pass
    route = default_route_ip()
    if route:
        names.add(route)
    host = (host or "").strip().strip("[]")
    if host and host not in ("0.0.0.0", "::"):
        names.add(host)
    valid = []
    for name in sorted(names):
        try:
            _split_names([name])
            valid.append(name)
        except CertError:
            continue
    return valid


def _issued_by_ca(cert_path: Path, data_dir: Path) -> bool:
    x509, *_ = _crypto()
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    ca = x509.load_pem_x509_certificate(ca_paths(data_dir)[0].read_bytes())
    try:
        cert.verify_directly_issued_by(ca)
        return True
    except Exception:  # noqa: BLE001  签名不对（InvalidSignature）、算法不符都算不是
        return False


def ensure_server_cert(data_dir: Path, names: list[str], *, force: bool = False,
                       remove: list[str] | None = None) -> tuple[Path, Path]:
    """服务端自己的证书：缺了、地址不全、快到期、不是当前 CA 签的（或 force）就重签；
    重签时保留旧证书里的地址（remove 里列的除外），其余情况原样用。"""
    cert_path, key_path = server_paths(data_dir)
    ensure_ca(data_dir)
    dropped = {n.strip().strip("[]").lower() for n in (remove or [])}
    if cert_path.is_file() and key_path.is_file():
        info = cert_info(cert_path)
        wanted_dns, wanted_ips = _split_names(names)
        have = {n.lower() for n in info["names"]}
        if (not force and not dropped and info["days_left"] > RENEW_BEFORE_DAYS
                and _issued_by_ca(cert_path, data_dir)
                and all(n in have for n in wanted_dns + wanted_ips)):
            return cert_path, key_path
        names = list(set(names) | set(info["names"]))
    names = [n for n in names if n.strip().strip("[]").lower() not in dropped]
    issue(data_dir, names, cert_path, key_path, common_name=socket.gethostname()[:64],
          private_dir=True)
    return cert_path, key_path


def is_builtin(data_dir: Path, tls_cert: str) -> bool:
    """部署用的服务器证书是不是内置 CA 签的那张（决定连接串要不要带 #ca=）。"""
    cert_path, _ = server_paths(data_dir)
    ca_cert, _ = ca_paths(data_dir)
    if not tls_cert or not ca_cert.is_file():
        return False
    try:
        return Path(tls_cert).expanduser().resolve() == cert_path.resolve()
    except OSError:
        return False
