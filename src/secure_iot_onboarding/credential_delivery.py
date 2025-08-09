"""Credential packaging and simulated secure delivery.

Functions:
    package_credentials(device_id) -> path to password protected ZIP containing:
        * device.key
        * device.crt
        * ca.crt
    generate_download_link(zip_path, expiry_minutes) -> simulated temporary URL

Security notes:
    * For real deployments replace simulated link with signed pre-signed URL (S3, GCS, etc.)
    * Consider one-time download semantics (delete after first retrieval)
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta
import secrets
import json
from typing import Optional

import pyzipper


BASE_CERTS = Path(__file__).resolve().parent.parent.parent / "certs"
DOWNLOAD_META = Path("./data/download_links.json")


def package_credentials(device_id: str, password: Optional[str] = None) -> str:
    """Create a password protected ZIP for a device's credentials.

    Returns path to ZIP. Generates a random password if none supplied (not returned here).
    """
    device_dir = BASE_CERTS / "devices" / device_id
    key_path = device_dir / "device.key"
    cert_path = device_dir / "device.crt"
    ca_crt = BASE_CERTS / "ca.crt"
    if not (key_path.exists() and cert_path.exists() and ca_crt.exists()):
        raise FileNotFoundError(
            "Required credential files missing; ensure registration completed."
        )

    zip_path = device_dir / "credentials.zip"
    password = password or secrets.token_urlsafe(12)
    with pyzipper.AESZipFile(
        zip_path,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(password.encode())
        zf.writestr(
            "README.txt",
            "Keep this archive secure. Password provided out-of-band.",
        )
        zf.write(key_path, arcname="device.key")
        zf.write(cert_path, arcname="device.crt")
        zf.write(ca_crt, arcname="ca.crt")
    return str(zip_path)


def generate_download_link(zip_path: str, expiry_minutes: int = 30) -> str:
    """Simulate generating a temporary signed URL.

    Stores metadata in a JSON file; a production system would integrate with object storage.
    """
    token = secrets.token_urlsafe(24)
    expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)
    record = {"path": zip_path, "expires_at": expires_at.isoformat()}
    DOWNLOAD_META.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if DOWNLOAD_META.exists():
        try:
            existing = json.loads(DOWNLOAD_META.read_text())
        except json.JSONDecodeError:
            existing = {}
    existing[token] = record
    DOWNLOAD_META.write_text(json.dumps(existing, indent=2))
    return f"https://local-download/{token}"


__all__ = ["package_credentials", "generate_download_link"]
