import os
import tempfile
from datetime import datetime, timedelta

from src.secure_iot_onboarding import db as db_module


def setup_temp_db(monkeypatch, tmp_path):
	db_url = f"sqlite:///{tmp_path}/test.db"
	monkeypatch.setenv("DEVICE_DB_URL", db_url)
	# Re-import to rebind engine if needed (simpler for this minimal test suite)
	from importlib import reload
	reload(db_module)
	db_module.init_db()


def test_add_and_get_device(monkeypatch, tmp_path):
	setup_temp_db(monkeypatch, tmp_path)
	d = db_module.add_device(name="sensor1", type="temp")
	fetched = db_module.get_device(d.id)
	assert fetched.id == d.id
	assert fetched.name == "sensor1"


def test_revoke_device(monkeypatch, tmp_path):
	setup_temp_db(monkeypatch, tmp_path)
	d = db_module.add_device(name="sensor2", type="temp")
	cert = db_module.add_certificate(d.id, "fingerprint123", datetime.utcnow() + timedelta(days=1))
	db_module.revoke_device(d.id)
	fetched = db_module.get_device(d.id)
	assert fetched.status == "revoked"
	assert fetched.certificate.revoked is True

