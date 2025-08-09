"""Certificate Authority logic for issuing and revoking device certificates.

Responsibilities:
  * Maintain CA root key/cert (RSA 2048, SHA256)
  * Generate per-device key pairs & CSRs
  * Sign CSRs producing device certs
  * Track revoked certificates & generate a CRL

Storage Layout (under ./certs/):
  certs/
    ca.key
    ca.crt
    crl.pem
    devices/<device_id>/
        device.key
        device.csr
        device.crt

Simplifications:
  * CRL maintained locally (no distribution endpoint yet)
  * Revocation tracked via a plaintext registry file (revoked.txt)
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta
from typing import Tuple
import threading

from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = Path(__file__).resolve().parent.parent.parent / "certs"
DEVICES_DIR = BASE_DIR / "devices"
REVOCATION_FILE = BASE_DIR / "revoked.txt"
CRL_FILE = BASE_DIR / "crl.pem"
CA_KEY_PATH = BASE_DIR / "ca.key"
CA_CERT_PATH = BASE_DIR / "ca.crt"

_lock = threading.RLock()


def ensure_dirs():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    DEVICES_DIR.mkdir(parents=True, exist_ok=True)


def ensure_ca_root(valid_years: int = 10):
    """Ensure CA root key and certificate exist; create if absent."""
    ensure_dirs()
    if CA_KEY_PATH.exists() and CA_CERT_PATH.exists():
        return

    with _lock:
        if CA_KEY_PATH.exists() and CA_CERT_PATH.exists():  # double-checked
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Secure IoT CA"),
        ])
        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder() .subject_name(subject) .issuer_name(issuer) .public_key(
                key.public_key()) .serial_number(
                x509.random_serial_number()) .not_valid_before(
                now -
                timedelta(
                    minutes=1)) .not_valid_after(
                        now +
                        timedelta(
                            days=365 *
                            valid_years)) .add_extension(
                                x509.BasicConstraints(
                                    ca=True,
                                    path_length=None),
                critical=True) .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    key.public_key()),
                critical=False) .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    key.public_key()),
                critical=False) .sign(
                private_key=key,
                algorithm=hashes.SHA256()))
        CA_KEY_PATH.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _load_ca():
    ensure_ca_root()
    key = serialization.load_pem_private_key(
        CA_KEY_PATH.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    return key, cert


def generate_keypair(device_id) -> Tuple[str, str]:
    """Generate RSA keypair & a CSR for the device.

    Returns (key_path, csr_path).
    """
    ensure_dirs()
    device_dir = DEVICES_DIR / str(device_id)
    device_dir.mkdir(parents=True, exist_ok=True)
    key_path = device_dir / "device.key"
    csr_path = device_dir / "device.csr"
    if key_path.exists() and csr_path.exists():
        return str(key_path), str(csr_path)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, str(device_id)),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return str(key_path), str(csr_path)


def sign_certificate(csr_path: str, device_id) -> Tuple[str, str, datetime]:
    """Sign a CSR returning (cert_path, fingerprint, not_after)."""
    with _lock:
        ca_key, ca_cert = _load_ca()
        csr = x509.load_pem_x509_csr(Path(csr_path).read_bytes())
        now = datetime.utcnow()
        not_after = now + timedelta(days=365)
        cert = (
            x509.CertificateBuilder() .subject_name(
                csr.subject) .issuer_name(
                ca_cert.subject) .public_key(
                csr.public_key()) .serial_number(
                    x509.random_serial_number()) .not_valid_before(
                        now -
                        timedelta(
                            minutes=1)) .not_valid_after(not_after) .add_extension(
                                x509.BasicConstraints(
                                    ca=False,
                                    path_length=None),
                critical=True) .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(
                            str(device_id))]),
                critical=False) .sign(
                ca_key,
                hashes.SHA256()))
        device_dir = DEVICES_DIR / str(device_id)
        device_dir.mkdir(parents=True, exist_ok=True)
        cert_path = device_dir / "device.crt"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        return str(cert_path), fingerprint, not_after


def revoke_certificate(fingerprint: str):
    """Mark a certificate fingerprint as revoked and regenerate CRL."""
    with _lock:
        ensure_dirs()
        existing = set()
        if REVOCATION_FILE.exists():
            existing = {line.strip() for line in REVOCATION_FILE.read_text(
            ).splitlines() if line.strip()}
        if fingerprint not in existing:
            with REVOCATION_FILE.open("a") as f:
                f.write(fingerprint + "\n")
        create_crl()


def create_crl():
    """Generate a simple PEM file enumerating revoked fingerprints 
    (placeholder CRL)."""
    ensure_dirs()
    revoked = []
    if REVOCATION_FILE.exists():
        revoked = [line.strip() for line in REVOCATION_FILE.read_text(
        ).splitlines() if line.strip()]
    # Simple text-based CRL (not a real X.509 CRL for brevity) – extend as
    # needed
    content = ["-----BEGIN REVOKED FINGERPRINT LIST-----"] + \
        revoked + ["-----END REVOKED FINGERPRINT LIST-----"]
    CRL_FILE.write_text("\n".join(content))


__all__ = [
    "ensure_ca_root",
    "generate_keypair",
    "sign_certificate",
    "revoke_certificate",
    "create_crl",
]
