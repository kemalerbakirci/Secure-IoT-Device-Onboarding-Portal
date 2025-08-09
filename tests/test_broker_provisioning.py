from pathlib import Path

from src.secure_iot_onboarding import broker_provisioning as bp


def test_add_and_remove_acl(monkeypatch, tmp_path):
	acl_path = tmp_path / "mosquitto.acl"
	monkeypatch.setenv("MOSQUITTO_ACL_FILE", str(acl_path))
	# Re-import to refresh ACL_FILE path
	from importlib import reload
	reload(bp)
	bp.add_device_acl("device123", ["devices/device123/#"])
	content = acl_path.read_text()
	assert "user device123" in content
	bp.remove_device_acl("device123")
	content2 = acl_path.read_text()
	assert "device123" not in content2

