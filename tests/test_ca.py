import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from src.secure_iot_onboarding import ca


def test_generate_keypair_and_sign(tmp_path, monkeypatch):
    # Redirect cert base dir
    monkeypatch.setattr(ca, "BASE_DIR", tmp_path / "certs")
    monkeypatch.setattr(ca, "DEVICES_DIR", tmp_path / "certs" / "devices")
    monkeypatch.setattr(ca, "CA_KEY_PATH", tmp_path / "certs" / "ca.key")
    monkeypatch.setattr(ca, "CA_CERT_PATH", tmp_path / "certs" / "ca.crt")
    monkeypatch.setattr(
        ca,
        "REVOCATION_FILE",
        tmp_path /
        "certs" /
        "revoked.txt")
    monkeypatch.setattr(ca, "CRL_FILE", tmp_path / "certs" / "crl.pem")

    ca.ensure_ca_root()
    key_path, csr_path = ca.generate_keypair("device-1")
    assert Path(key_path).exists()
    assert Path(csr_path).exists()
    cert_path, fingerprint, not_after = ca.sign_certificate(
        csr_path, "device-1")
    assert Path(cert_path).exists()
    pem = Path(cert_path).read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    assert cert.fingerprint(hashes.SHA256()).hex() == fingerprint
    assert not_after > cert.not_valid_before


def test_revoke_and_crl(tmp_path, monkeypatch):
    monkeypatch.setattr(ca, "BASE_DIR", tmp_path / "certs")
    monkeypatch.setattr(ca, "DEVICES_DIR", tmp_path / "certs" / "devices")
    monkeypatch.setattr(ca, "CA_KEY_PATH", tmp_path / "certs" / "ca.key")
    monkeypatch.setattr(ca, "CA_CERT_PATH", tmp_path / "certs" / "ca.crt")
    monkeypatch.setattr(
        ca,
        "REVOCATION_FILE",
        tmp_path /
        "certs" /
        "revoked.txt")
    monkeypatch.setattr(ca, "CRL_FILE", tmp_path / "certs" / "crl.pem")

    ca.ensure_ca_root()
    key_path, csr_path = ca.generate_keypair("device-2")
    cert_path, fingerprint, _ = ca.sign_certificate(csr_path, "device-2")
    ca.revoke_certificate(fingerprint)
    assert ca.REVOCATION_FILE.read_text().strip() == fingerprint
    ca.create_crl()
    crl_text = ca.CRL_FILE.read_text()
    assert fingerprint in crl_text
