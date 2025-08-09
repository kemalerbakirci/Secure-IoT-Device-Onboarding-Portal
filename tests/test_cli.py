from click.testing import CliRunner
import json

from src.secure_iot_onboarding import cli


class _Resp:
    def __init__(self, status_code=201, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload


def test_cli_register(monkeypatch):
    runner = CliRunner()

    def fake_post(url, json=None, timeout=30):  # noqa: A002
        return _Resp(
            201,
            {
                "device_id": "abcd",
                "certificate_fingerprint": "ff0011",
                "certificate_expires_at": "2030-01-01T00:00:00",
                "credentials_link": "https://local-download/token",
            },
        )

    monkeypatch.setattr(cli, "requests", type("Req", (), {"post": fake_post}))

    result = runner.invoke(
        cli.main,
        [
            "register",
            "--name",
            "dev1",
            "--type",
            "temp",
            "--location",
            "lab",
            "--firmware",
            "1.0.0",
        ],
    )
    assert result.exit_code == 0
    assert "Device registered" in result.output
    assert "credentials link".lower() in result.output.lower()


def test_cli_revoke(monkeypatch):
    runner = CliRunner()

    def fake_post(url, timeout=30):  # simple revoke response
        return _Resp(200, {"status": "revoked", "device_id": "abcd"})

    monkeypatch.setattr(cli, "requests", type("Req", (), {"post": fake_post}))
    result = runner.invoke(cli.main, ["revoke", "abcd"])
    assert result.exit_code == 0
    assert "revoked" in result.output.lower()
