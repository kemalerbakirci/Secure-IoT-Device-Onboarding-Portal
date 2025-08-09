"""Command-line interface for Secure IoT Device Onboarding Portal."""
from __future__ import annotations

import click
import requests
from tabulate import tabulate
import os

API_BASE = os.environ.get("ONBOARDING_API", "http://localhost:5000")


@click.group()
def main():
	"""CLI for managing device onboarding (register, list, revoke)."""


@main.command()
@click.option("--name", required=True, help="Device name")
@click.option("--type", required=True, help="Device type")
@click.option("--location", required=False, help="Physical location")
@click.option("--firmware", required=False, help="Firmware version")
def register(name, type, location, firmware):
	"""Register a new device via API."""
	payload = {"name": name, "type": type, "location": location, "firmware": firmware}
	r = requests.post(f"{API_BASE}/register", json=payload, timeout=30)
	if r.status_code >= 300:
		click.echo(f"Error: {r.status_code} {r.text}")
		raise SystemExit(1)
	data = r.json()
	click.echo("Device registered:")
	click.echo(tabulate([[data['device_id'], data['certificate_fingerprint'], data['certificate_expires_at']]], headers=["ID", "Fingerprint", "Expires"]))
	click.echo(f"Credentials link: {data['credentials_link']}")


@main.command()
def list():  # pragma: no cover - simple convenience wrapper
	"""List devices (basic: requires direct DB or additional endpoint future)."""
	click.echo("Listing devices not yet implemented via API; extend backend with /devices endpoint.")


@main.command()
@click.argument("device_id")
def revoke(device_id):
	"""Revoke device certificate by ID."""
	r = requests.post(f"{API_BASE}/revoke/{device_id}", timeout=30)
	if r.status_code >= 300:
		click.echo(f"Error: {r.status_code} {r.text}")
		raise SystemExit(1)
	click.echo("Revoked:")
	click.echo(r.json())


if __name__ == "__main__":  # pragma: no cover
	main()

