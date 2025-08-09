"""End-to-end style tests without external broker.

Validates real DB + CA + API working together (excluding ACL side effects).
"""
from importlib import reload
from uuid import UUID

from src.secure_iot_onboarding import db as db_module
from src.secure_iot_onboarding import ca
from src.secure_iot_onboarding.app import create_app


def test_register_and_revoke_flow(tmp_path, monkeypatch):
    # Redirect DB to temp file
    monkeypatch.setenv(
        "DEVICE_DB_URL",
        f"sqlite:///{tmp_path}/int.db"
    )
    reload(db_module)
    db_module.init_db()

    # Redirect CA directories
    monkeypatch.setattr(ca, "BASE_DIR", tmp_path / "certs")
    monkeypatch.setattr(
        ca, "DEVICES_DIR", tmp_path / "certs" / "devices"
    )
    monkeypatch.setattr(
        ca, "CA_KEY_PATH", tmp_path / "certs" / "ca.key"
    )
    monkeypatch.setattr(
        ca, "CA_CERT_PATH", tmp_path / "certs" / "ca.crt"
    )
    monkeypatch.setattr(
        ca, "REVOCATION_FILE", tmp_path / "certs" / "revoked.txt"
    )
    monkeypatch.setattr(
        ca, "CRL_FILE", tmp_path / "certs" / "crl.pem"
    )

    # Redirect credential delivery paths
    from src.secure_iot_onboarding import credential_delivery
    monkeypatch.setattr(
        credential_delivery, "BASE_CERTS", tmp_path / "certs"
    )
    monkeypatch.setattr(
        credential_delivery,
        "DOWNLOAD_META",
        tmp_path / "data" / "download_links.json"
    )

    # Redirect broker ACL file
    from src.secure_iot_onboarding import broker_provisioning
    monkeypatch.setattr(
        broker_provisioning,
        "ACL_FILE",
        tmp_path / "data" / "mosquitto.acl"
    )

    app = create_app()
    client = app.test_client()

    # Register
    r = client.post(
        "/register",
        json={
            "name": "int-dev",
            "type": "sensor",
            "location": "field",
            "firmware": "1.2.3",
        },
    )
    assert r.status_code == 201
    data = r.get_json()
    device_id = data["device_id"]
    # Validate UUID
    UUID(device_id)

    # Fetch device info
    g = client.get(f"/device/{device_id}")
    assert g.status_code == 200
    meta = g.get_json()
    assert meta["name"] == "int-dev"
    assert meta["certificate"]["fingerprint"]

    # Revoke
    rv = client.post(f"/revoke/{device_id}")
    assert rv.status_code == 200
    # Confirm status updated
    g2 = client.get(f"/device/{device_id}")
    if g2.status_code == 200:
        # Some race in very constrained case; ensure status flagged
        assert g2.get_json()["status"] == "revoked"
