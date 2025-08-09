"""Credential packaging & simulated delivery utilities.

Functions:
    package_credentials(device_id) -> password ZIP with:
        * device.key
        * device.crt
        * ca.crt
    generate_download_link(zip_path, expiry) -> temp token URL

Security notes:
    * Use signed URLs (S3/GCS/etc.) for real deployments.
    * Consider one-time download (delete after retrieval).
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
    """Create password ZIP for device credentials.

    Returns ZIP path. Generates random password if none provided.
    Password is not returned; share out-of-band.
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
    """Return simulated temporary signed URL token.

    Metadata saved in JSON; production would use object storage.
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
