"""Flask REST API for Secure IoT Device Onboarding Portal.

Endpoints:
  POST /register     - Register device, issue cert, provision broker, return credential package link.
  GET /device/<id>   - Get device metadata & certificate info.
  POST /revoke/<id>  - Revoke device certificate & remove broker access.

This module wires together DB (db.py), CA (ca.py), broker provisioning (broker_provisioning.py),
and credential delivery (credential_delivery.py).
"""
from __future__ import annotations

from flask import Flask, request, jsonify
from http import HTTPStatus
from uuid import UUID
from pydantic import BaseModel, Field, ValidationError
from typing import Optional
from datetime import datetime
import os

from . import db as db_module
from . import ca
from . import broker_provisioning
from . import credential_delivery


class DeviceRegistrationModel(BaseModel):
	name: str = Field(min_length=1, max_length=128)
	type: str = Field(min_length=1, max_length=64)
	location: Optional[str] = Field(default=None, max_length=128)
	firmware: Optional[str] = Field(default=None, max_length=64)


def create_app() -> Flask:
	app = Flask(__name__)

	db_module.init_db()  # Ensure tables exist (idempotent)

	@app.route("/register", methods=["POST"])
	def register():
		try:
			payload = DeviceRegistrationModel(**request.get_json(force=True))
		except ValidationError as ve:
			return jsonify({"error": "validation_error", "details": ve.errors()}), HTTPStatus.BAD_REQUEST
		except Exception:
			return jsonify({"error": "invalid_json"}), HTTPStatus.BAD_REQUEST

		# Add device to DB
		device = db_module.add_device(
			name=payload.name,
			type=payload.type,
			location=payload.location,
			firmware=payload.firmware,
		)

		# Generate key pair & CSR (simplified: directly generate and sign cert)
		key_path, csr_path = ca.generate_keypair(device.id)
		cert_path, fingerprint, not_after = ca.sign_certificate(csr_path, device.id)

		# Persist certificate metadata
		db_module.add_certificate(
			device_id=device.id,
			fingerprint=fingerprint,
			expires_at=not_after,
		)

		# Provision broker ACL
		broker_provisioning.add_device_acl(str(device.id), topics=[f"devices/{device.id}/#"])

		# Package credentials
		zip_path = credential_delivery.package_credentials(str(device.id))
		download_link = credential_delivery.generate_download_link(zip_path, expiry_minutes=30)

		return (
			jsonify(
				{
					"device_id": str(device.id),
					"certificate_fingerprint": fingerprint,
					"certificate_expires_at": not_after.isoformat(),
					"credentials_link": download_link,
				}
			),
			HTTPStatus.CREATED,
		)

	@app.route("/device/<device_id>", methods=["GET"])
	def get_device(device_id: str):
		try:
			UUID(device_id)
		except ValueError:
			return jsonify({"error": "invalid_device_id"}), HTTPStatus.BAD_REQUEST

		device = db_module.get_device(device_id)
		if not device:
			return jsonify({"error": "not_found"}), HTTPStatus.NOT_FOUND

		cert = device.certificate
		return (
			jsonify(
				{
					"id": str(device.id),
					"name": device.name,
					"type": device.type,
					"location": device.location,
					"firmware": device.firmware,
					"registered_at": device.registered_at.isoformat() if device.registered_at else None,
					"status": device.status,
					"certificate": {
						"fingerprint": cert.fingerprint if cert else None,
						"issued_at": cert.issued_at.isoformat() if cert and cert.issued_at else None,
						"expires_at": cert.expires_at.isoformat() if cert and cert.expires_at else None,
						"revoked": cert.revoked if cert else None,
					},
				}
			),
			HTTPStatus.OK,
		)

	@app.route("/revoke/<device_id>", methods=["POST"])
	def revoke(device_id: str):
		try:
			UUID(device_id)
		except ValueError:
			return jsonify({"error": "invalid_device_id"}), HTTPStatus.BAD_REQUEST

		device = db_module.get_device(device_id)
		if not device:
			return jsonify({"error": "not_found"}), HTTPStatus.NOT_FOUND

		cert = device.certificate
		if not cert:
			return jsonify({"error": "certificate_not_found"}), HTTPStatus.BAD_REQUEST

		# Revoke certificate (update CRL & DB)
		ca.revoke_certificate(cert.fingerprint)
		db_module.revoke_device(device_id)
		broker_provisioning.remove_device_acl(device_id)

		return jsonify({"status": "revoked", "device_id": device_id}), HTTPStatus.OK

	@app.route("/health", methods=["GET"])
	def health():
		return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()}), HTTPStatus.OK

	return app


app = create_app()

if __name__ == "__main__":  # pragma: no cover
	port = int(os.environ.get("PORT", "5000"))
	app.run(host="0.0.0.0", port=port)

