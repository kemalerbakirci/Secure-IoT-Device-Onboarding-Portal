import pytest
from unittest.mock import patch

from src.secure_iot_onboarding.app import create_app


@pytest.fixture()
def client():
	app = create_app()
	app.testing = True
	return app.test_client()


@patch("src.secure_iot_onboarding.app.db_module.add_device")
@patch("src.secure_iot_onboarding.app.ca.generate_keypair")
@patch("src.secure_iot_onboarding.app.ca.sign_certificate")
@patch("src.secure_iot_onboarding.app.db_module.add_certificate")
@patch("src.secure_iot_onboarding.app.broker_provisioning.add_device_acl")
@patch("src.secure_iot_onboarding.app.credential_delivery.package_credentials")
@patch("src.secure_iot_onboarding.app.credential_delivery.generate_download_link")
def test_register_device(mock_link, mock_package, mock_acl, mock_add_cert, mock_sign, mock_gen_key, mock_add_dev, client):
	mock_add_dev.return_value = type("Device", (), {"id": "1234"})
	mock_gen_key.return_value = ("/tmp/key", "/tmp/csr")
	mock_sign.return_value = ("/tmp/cert", "ABC123", __import__("datetime").datetime.utcnow())
	mock_add_cert.return_value = None
	mock_package.return_value = "/tmp/cred.zip"
	mock_link.return_value = "https://local/cred"

	resp = client.post("/register", json={"name": "dev1", "type": "sensor"})
	assert resp.status_code == 201
	data = resp.get_json()
	assert data["device_id"] == "1234"
	assert data["certificate_fingerprint"] == "ABC123"
	assert "credentials_link" in data


def test_get_device_not_found(client):
	resp = client.get("/device/11111111-1111-1111-1111-111111111111")
	assert resp.status_code in (400, 404)  # depends if DB layer returns None


@patch("src.secure_iot_onboarding.app.db_module.get_device")
@patch("src.secure_iot_onboarding.app.ca.revoke_certificate")
@patch("src.secure_iot_onboarding.app.db_module.revoke_device")
@patch("src.secure_iot_onboarding.app.broker_provisioning.remove_device_acl")
def test_revoke(mock_remove, mock_revoke_dev, mock_revoke_cert, mock_get_dev, client):
	cert = type("Cert", (), {"fingerprint": "FFF", "revoked": False})
	device = type(
		"Device",
		(),
		{"id": "11111111-1111-1111-1111-111111111111", "certificate": cert},
	)
	mock_get_dev.return_value = device
	resp = client.post("/revoke/11111111-1111-1111-1111-111111111111")
	assert resp.status_code == 200
	assert resp.get_json()["status"] == "revoked"

