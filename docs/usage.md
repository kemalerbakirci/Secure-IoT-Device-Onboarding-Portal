# Usage Guide

## 1. Clone Repository
```bash
git clone https://github.com/your-org/secure-iot-device-onboarding-portal.git
cd secure-iot-device-onboarding-portal
```

## 2. Create Virtual Environment & Install Dependencies
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Initialize Database
```bash
python -c "from src.secure_iot_onboarding.db import init_db; init_db()"
```

## 4. Generate CA Root (Optional)
Auto-generated on demand, but you can pre-create:
```bash
python -c "from src.secure_iot_onboarding import ca; ca.ensure_ca_root()"
```

## 5. Configure Mosquitto (Example)
Create a config snippet (mosquitto.conf):
```
listener 8883
cafile /absolute/path/to/certs/ca.crt
certfile /absolute/path/to/server.crt
keyfile /absolute/path/to/server.key
require_certificate true
use_identity_as_username true
acl_file /absolute/path/to/data/mosquitto.acl
```

Run broker (example):
```bash
mosquitto -c mosquitto.conf
```

## 6. Launch API
```bash
FLASK_APP=src.secure_iot_onboarding.app flask run
```

## 7. Register a Device
```bash
curl -X POST http://localhost:5000/register \
	-H 'Content-Type: application/json' \
	-d '{"name":"sensor-001","type":"temp","location":"lab","firmware":"1.0.0"}'
```
Response includes credentials link.

## 8. Download Credentials
Simulated link format: `https://local-download/<token>` – for local development inspect `data/download_links.json` for actual path.

## 9. Connect Device via MQTT (Example with mosquitto_pub)
```bash
mosquitto_pub --cafile certs/ca.crt \
	--cert certs/devices/<device_id>/device.crt \
	--key certs/devices/<device_id>/device.key \
	-h localhost -p 8883 -t devices/<device_id>/status -m "online" --tls-version tlsv1.2
```

## 10. Revoke a Device
```bash
curl -X POST http://localhost:5000/revoke/<device_id>
```

## 11. View CRL
```bash
cat certs/crl.pem
```

## Notes
* After packaging, you can optionally delete private keys for defense in depth.
* Extend with /devices listing endpoint for bulk queries.
* Integrate with cloud storage for real signed download links.

