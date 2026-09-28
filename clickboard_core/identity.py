"""Machine identity: a self-signed TLS certificate per machine, LAN addresses, and the passphrase key.

Part of clickboard_core. PolyForm Small Business License 1.0.0, see LICENSE.
"""
import datetime
import hashlib
import os
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import common as C


def ensure_identity(device_id: str) -> str:
    """Create this machine's TLS certificate on first run; return it as PEM."""
    if C.CERT_FILE.exists() and C.KEY_FILE.exists():
        return C.CERT_FILE.read_text()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"clickboard-{device_id}")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        # Self-signed and marked as its own CA, so a sibling can load it
        # directly as a trust anchor for mutual TLS.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    C.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    C.KEY_FILE.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        os.chmod(C.KEY_FILE, 0o600)
    except OSError:
        pass
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    C.CERT_FILE.write_text(pem)
    C.log("created this machine's certificate")
    return pem


def der_fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def lan_addrs() -> list:
    addrs = set()
    try:
        # Connecting a UDP socket sends nothing; it just picks the outgoing interface.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        addrs.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                addrs.add(ip)
    except OSError:
        pass
    return sorted(addrs)


def local_key(passphrase: str) -> bytes:
    """Slow on purpose, so a captured announcement can't be cheaply brute-forced."""
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=b"clickboard-local-v1",
                          n=2 ** 14, r=8, p=1, dklen=32)
