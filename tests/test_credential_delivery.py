import json
from pathlib import Path
import pyzipper
from datetime import datetime

from src.secure_iot_onboarding import ca
from src.secure_iot_onboarding import credential_delivery as cd


def test_package_and_generate_link(tmp_path, monkeypatch):
    # Redirect CA paths
    monkeypatch.setattr(ca, "BASE_DIR", tmp_path / "certs")
    monkeypatch.setattr(ca, "DEVICES_DIR", tmp_path / "certs" / "devices")
    monkeypatch.setattr(ca, "CA_KEY_PATH", tmp_path / "certs" / "ca.key")
    monkeypatch.setattr(ca, "CA_CERT_PATH", tmp_path / "certs" / "ca.crt")
    monkeypatch.setattr(ca, "REVOCATION_FILE", tmp_path / "certs" / "revoked.txt")
    monkeypatch.setattr(ca, "CRL_FILE", tmp_path / "certs" / "crl.pem")

    # Also patch credential delivery BASE_CERTS constant
    monkeypatch.setattr(cd, "BASE_CERTS", tmp_path / "certs")
    monkeypatch.setattr(cd, "DOWNLOAD_META", tmp_path / "data" / "download_links.json")

    ca.ensure_ca_root()
    key_path, csr_path = ca.generate_keypair("dev-cred")
    cert_path, fingerprint, _ = ca.sign_certificate(csr_path, "dev-cred")

    password = "TestPass123!"
    zip_path = cd.package_credentials("dev-cred", password=password)
    assert Path(zip_path).exists()

    # Open and verify archive contents
    with pyzipper.AESZipFile(zip_path, 'r') as zf:
        zf.setpassword(password.encode())
        names = zf.namelist()
        assert {"device.key", "device.crt", "ca.crt", "README.txt"}.issubset(set(names))

    link = cd.generate_download_link(zip_path, expiry_minutes=5)
    assert link.startswith("https://local-download/")
    meta = json.loads(Path(cd.DOWNLOAD_META).read_text())
    assert len(meta) == 1
    token, record = next(iter(meta.items()))
    assert record["path"].endswith("credentials.zip")
    # Basic ISO timestamp parse (no tz handling needed here)
    datetime.fromisoformat(record["expires_at"])  # should not raise
