# Secure IoT Device Onboarding Portal

![MQTT](https://img.shields.io/badge/MQTT-660066?style=for-the-badge&logo=mqtt&logoColor=white)
![Security](https://img.shields.io/badge/Security-X.## 📄 License
MIT License. See the [LICENSE](LICENSE) file for details.9_PKI-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![TLS](https://img.shields.io/badge/TLS-mTLS_Auth-green?style=for-the-badge)

## 🚀 Elevator Pitch
Bootstrapping IoT devices securely at scale is hard: keys must be unique, certificates must be signed and revocable, broker access must be controlled, and credentials must be delivered safely. **Secure IoT Device Onboarding Portal** automates secure onboarding using X.509 certificates, a lightweight internal Certificate Authority (CA), a device registry, broker ACL provisioning for **MQTT (mTLS)**, and controlled credential packaging / delivery.

## 🧱 Architecture Overview
```text
													+---------------------------+
													|        Operator / CLI     |
													+-------------+-------------+
																				|
																				| REST (register / revoke / query)
																				v
													+---------------------------+
													|        Flask API          |
													|  (app.py)                 |
													+----+----------+-----------+
															 |          |
			(cert issue / revoke)    |          | (ACL manage)
															 v          v
											+---------------+  +------------------+
											|   CA Module   |  |  Broker Provision|
											|   (ca.py)     |  | (broker_*.py)    |
											+-------+-------+  +---------+--------+
															|                     |
										(certs/, CRL)          (mosquitto ACL file)
															|                     |
															v                     |
											+---------------+             |
											| Credential    |             |
											| Delivery      |<------------+
											| (packaging)   |
											+-------+-------+
															|
															| (password protected ZIP + signed link)
															v
												Device Manufacturer

											+--------------------+
											|   Device Runtime   |
											|  (MQTT mTLS conn)  |
											+---------+----------+
																|
																| TLS (Client Cert + CA Root)
																v
												 +-------------+
												 |  MQTT Broker|
												 +-------------+
```

## ✨ Features
* 🔐 **Automated X.509 certificate issuance** (device certificates, RSA 2048, SHA256)
* 🔄 **Certificate lifecycle management**: issue, revoke, CRL generation
* 📊 **Device registry** (metadata + status + certificate linkage)
* 📡 **MQTT broker ACL provisioning** (grant / revoke topic access)
* 📦 **Secure credential packaging** (password protected ZIP bundles)
* ⚡ **CLI tooling** for operator workflows
* 🌐 **REST API** for integration or UI extension
* 🗄️ **Extensible storage** (SQLite default, PostgreSQL ready)

## 🛠 Tech Stack
* ![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white) **Python 3.9 - 3.11**
* ![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white) **Flask (REST API)**
* ![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-red?style=flat) **SQLAlchemy (ORM) / SQLite or PostgreSQL**
* ![Cryptography](https://img.shields.io/badge/Cryptography-X.509-blue?style=flat) **cryptography (X.509, key management)**
* ![MQTT](https://img.shields.io/badge/MQTT-paho--mqtt-660066?style=flat) **paho-mqtt (broker interaction / future extensions)**
* ![Security](https://img.shields.io/badge/Security-pyzipper-green?style=flat) **pyzipper (encrypted credential bundles)**
* ![CLI](https://img.shields.io/badge/CLI-click-orange?style=flat) **click + requests + tabulate (CLI tooling)**
* ![Testing](https://img.shields.io/badge/Testing-pytest-yellow?style=flat) **pytest / pytest-mock (testing)**

## 📦 Installation
Prerequisites:
* Python 3.11
* (Optional) Mosquitto MQTT broker installed & configured for TLS/mTLS

Steps:
```bash
git clone https://github.com/your-org/secure-iot-device-onboarding-portal.git
cd secure-iot-device-onboarding-portal

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate

pip install --upgrade pip
pip install -r requirements.txt

# Initialize database (SQLite default)
python -c "from src.secure_iot_onboarding.db import init_db; init_db()"

# (Optional) Pre-generate CA root (auto-generated on first use otherwise)
python -c "from src.secure_iot_onboarding import ca; ca.ensure_ca_root()"

# Run API
FLASK_APP=src.secure_iot_onboarding.app flask run
```

### Mosquitto Broker (Example Minimal mTLS Config Snippet)
```
listener 8883
cafile /path/to/ca.crt
certfile /path/to/server.crt
keyfile /path/to/server.key
require_certificate true
use_identity_as_username true
acl_file /path/to/mosquitto.acl
```

## ▶️ Usage Examples

### Register a Device (REST)
```bash
curl -X POST http://localhost:5000/register \
	-H 'Content-Type: application/json' \
	-d '{"name":"sensor-001","type":"temp","location":"lab","firmware":"1.0.0"}'
```

### Fetch Device Metadata
```bash
curl http://localhost:5000/device/<device_id>
```

### Revoke a Device Certificate
```bash
curl -X POST http://localhost:5000/revoke/<device_id>
```

### CLI Equivalent
```bash
python -m src.secure_iot_onboarding.cli register --name sensor-001 --type temp --location lab --firmware 1.0.0
python -m src.secure_iot_onboarding.cli list
python -m src.secure_iot_onboarding.cli revoke <device_id>
```

## 🔐 Security Considerations
* Mutual TLS (mTLS) enforced at broker: client cert maps to device identity.
* Certificates: RSA 2048, SHA256 signatures.
* Revocation: Local CRL (extendable to OCSP / distribution point publishing).
* Private Keys: Device private keys packaged once; server copy can be purged post-delivery.
* Password-protected ZIP for credential transport (out-of-band password recommendation).
* Principle of least privilege via topic-scoped ACLs.
* Auditing potential: DB stores issuance & revocation timestamps.

## 🧪 Testing
```bash
pytest -q
```

For coverage (after installing pytest-cov):
```bash
pytest --cov=src/secure_iot_onboarding --cov-report=term-missing
```

## 📘 Further Learning
For a detailed conceptual deep dive (PKI concepts, threat model, scaling & hardening guidance) see: [docs/learning.md](docs/learning.md)

## 🤝 Contributing
1. Fork & branch (`feature/your-idea`)
2. Write tests for new functionality
3. Run lint & tests (`flake8 && pytest`)
4. Submit PR with detailed description / rationale

## � **Comprehensive Documentation**

This project includes extensive educational documentation covering all aspects of secure IoT infrastructure:

### 📖 **Documentation Suite**
- **[📋 Documentation Index](docs/documentation-index.md)** - Complete guide to all available documentation
- **[🎓 Main Learning Guide](docs/learning.md)** - Comprehensive system overview and concepts
- **[🔐 PKI Fundamentals](docs/pki-fundamentals.md)** - Deep dive into Public Key Infrastructure for IoT
- **[📡 MQTT Security](docs/mqtt-security.md)** - Complete guide to MQTT broker security and access control
- **[🛡️ Threat Modeling](docs/threat-modeling.md)** - Security threats, attack scenarios, and mitigation strategies
- **[🚀 Production Deployment](docs/production-deployment.md)** - Production deployment guide with security hardening

### 🎯 **Learning Paths by Role**
- **Security Engineers**: Start with threat modeling and PKI fundamentals
- **DevOps Engineers**: Focus on production deployment and MQTT security
- **IoT Developers**: Begin with the main learning guide and PKI concepts
- **System Architects**: Review threat modeling and production deployment

**Total: 90+ pages** of comprehensive educational content covering everything from basic concepts to production deployment.

## �📄 License
MIT License. See the LICENSE file (to be added) for details.

## 🗺 Roadmap (Ideas)
* Device attestation integration
* OCSP responder / CRL distribution endpoint
* Web dashboard UI
* Hardware secure element (HSM) support for CA key

---
Happy building secure IoT systems! 🔐

