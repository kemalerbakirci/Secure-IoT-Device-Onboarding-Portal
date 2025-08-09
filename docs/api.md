# API Documentation

Base URL: `http://localhost:5000`

## Error Format
```json
{ "error": "error_code", "details": optional_details }
```

## POST /register
Register a device and issue credentials.

### Request Body
```json
{
	"name": "sensor-001",
	"type": "temp",
	"location": "lab",
	"firmware": "1.0.0"
}
```

### Responses
201 Created
```json
{
	"device_id": "<uuid>",
	"certificate_fingerprint": "<hex>",
	"certificate_expires_at": "2025-08-09T12:34:56.000000",
	"credentials_link": "https://local-download/<token>"
}
```

400 Validation error
```json
{ "error": "validation_error", "details": [ ... ] }
```

## GET /device/<id>
Retrieve device metadata & certificate info.

### Response
200 OK
```json
{
	"id": "<uuid>",
	"name": "sensor-001",
	"type": "temp",
	"location": "lab",
	"firmware": "1.0.0",
	"registered_at": "2025-08-09T12:34:56.000000",
	"status": "active",
	"certificate": {
		"fingerprint": "<hex>",
		"issued_at": "2025-08-09T12:34:56.000000",
		"expires_at": "2026-08-09T12:34:56.000000",
		"revoked": false
	}
}
```

404 Not found
```json
{ "error": "not_found" }
```

## POST /revoke/<id>
Revoke a device certificate & remove broker ACL.

### Response
200 OK
```json
{ "status": "revoked", "device_id": "<uuid>" }
```

404 Not found
```json
{ "error": "not_found" }
```

## GET /health
Health probe endpoint.

### Response
```json
{ "status": "ok", "time": "2025-08-09T12:34:56.000000" }
```

## Example curl Commands
```bash
curl -X POST http://localhost:5000/register \
	-H 'Content-Type: application/json' \
	-d '{"name":"sensor-001","type":"temp","location":"lab","firmware":"1.0.0"}'

curl http://localhost:5000/device/<uuid>

curl -X POST http://localhost:5000/revoke/<uuid>
```

