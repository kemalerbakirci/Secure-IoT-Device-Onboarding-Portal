# 🏗️ Secure IoT Device Onboarding Portal - Architecture

## 🎯 System Overview

The Secure IoT Device Onboarding Portal provides automated certificate-based device registration, credential provisioning, and secure MQTT broker access management for IoT deployments.

## 🧱 Architecture Diagram

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            🏢 ENTERPRISE ZONE                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    HTTP/JSON     ┌──────────────────────────────────────┐  │
│  │   🧑‍💻 Operator    │ ──────────────► │          🌐 REST API                │  │
│  │   CLI Client    │                  │      (Flask Application)            │  │
│  │                 │                  │         Port: 5000                   │  │
│  └─────────────────┘                  └──────────┬───────────────────────────┘  │
│                                                   │                              │
│  ┌─────────────────┐                              │                              │
│  │  📱 Web Portal   │ ─────────────────────────────┘                              │
│  │  (Future)       │                                                             │
│  └─────────────────┘                                                             │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                            📊 APPLICATION LAYER                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│                    ┌──────────────────────────────────────┐                     │
│                    │          🔧 Core Services            │                     │
│                    │                                      │                     │
│    ┌───────────────┼─────────┐  ┌─────────────┐  ┌────────┼──────────────┐      │
│    │ 🗄️ Database    │         │  │ 🔐 CA Core  │  │ 📦 Credential │      │      │
│    │   Module      │         │  │   Module    │  │   Delivery    │      │      │
│    │  (db.py)      │         │  │  (ca.py)    │  │ (credential_  │      │      │
│    │               │         │  │             │  │  delivery.py) │      │      │
│    │ • Device CRUD │         │  │ • X.509 Gen │  │ • ZIP Package │      │      │
│    │ • Cert Meta   │         │  │ • Key Pairs │  │ • Secure Links│      │      │
│    │ • SQLite      │         │  │ • CRL Mgmt  │  │ • Download    │      │      │
│    └───────┬───────┘         │  │ • CA Root   │  │   Management  │      │      │
│            │                 │  └─────┬───────┘  └───────┬───────┘      │      │
│            │                 │        │                  │              │      │
│            │                 │        │                  │              │      │
│    ┌───────▼─────────────────┼────────▼──────────────────▼──────────────┼──┐   │
│    │                🎯 REST API ORCHESTRATOR                            │  │   │
│    │                        (app.py)                                    │  │   │
│    │                                                                    │  │   │
│    │  📍 Endpoints:                                                     │  │   │
│    │  • POST /register  → Device Registration + Cert Issue             │  │   │
│    │  • GET  /device/<id> → Device Status & Certificate Info           │  │   │
│    │  • POST /revoke/<id> → Certificate Revocation + ACL Removal       │  │   │
│    │  • GET  /health     → System Health Check                         │  │   │
│    │                                                                    │  │   │
│    └────────────────────────┬───────────────────────────────────────────┼──┘   │
│                             │                                           │      │
│                             │                                           │      │
│    ┌────────────────────────▼──────────────┐  ┌────────────────────────┼──┐   │
│    │     🛡️ Broker Provisioning             │  │   🔒 Certificate        │  │   │
│    │        Module                          │  │     Storage             │  │   │
│    │  (broker_provisioning.py)             │  │                         │  │   │
│    │                                       │  │  📂 certs/              │  │   │
│    │  • ACL Management                     │  │  ├── ca.crt             │  │   │
│    │  • Topic Permissions                 │  │  ├── ca.key             │  │   │
│    │  • Mosquitto Integration             │  │  ├── crl.pem            │  │   │
│    │  • Dynamic Updates                   │  │  └── devices/           │  │   │
│    └───────────────┬───────────────────────┘  │      └── <device-id>/  │  │   │
│                    │                          │          ├── device.key│  │   │
│                    │                          │          ├── device.crt│  │   │
│                    │                          │          └── creds.zip │  │   │
│                    │                          └─────────────────────────┼──┘   │
├────────────────────┼─────────────────────────────────────────────────────────────┤
│                    │                  💾 PERSISTENCE LAYER                     │
├────────────────────┼─────────────────────────────────────────────────────────────┤
│                    │                                                           │
│                    ▼                                                           │
│          ┌─────────────────────┐      ┌─────────────────────┐                  │
│          │   📄 ACL Config      │      │   🗃️ Device DB       │                  │
│          │  mosquitto.acl      │      │   devices.db        │                  │
│          │                     │      │  (SQLite)           │                  │
│          │ user device123:     │      │                     │                  │
│          │ topic read dev123/# │      │ Tables:             │                  │
│          │ topic write dev123/#│      │ • devices           │                  │
│          └─────────────────────┘      │ • certificates      │                  │
│                                       └─────────────────────┘                  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                           🌐 DEPLOYMENT ZONE                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                      🏭 Device Manufacturing                            │   │
│   │                                                                         │   │
│   │  1️⃣ Register Device    2️⃣ Download Creds    3️⃣ Flash Firmware         │   │
│   │     via CLI/API    ──►    via Secure Link ──►   with Certificates       │   │
│   │                                                                         │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                     │
│                                           │ Secure Provisioning                 │
│                                           ▼                                     │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                     🌍 PRODUCTION ENVIRONMENT                           │   │
│   │                                                                         │   │
│   │  ┌─────────────────┐             mTLS Connection           ┌──────────┐ │   │
│   │  │  📱 IoT Device   │ ◄──────────────────────────────────► │ 🦟 MQTT  │ │   │
│   │  │                 │                                      │  Broker  │ │   │
│   │  │ • Client Cert   │    Authenticated Topics:             │          │ │   │
│   │  │ • Private Key   │    devices/{device-id}/#             │ • mTLS   │ │   │
│   │  │ • CA Root Cert  │                                      │ • ACL    │ │   │
│   │  │ • Device ID     │                                      │ • CRL    │ │   │
│   │  └─────────────────┘                                      └──────────┘ │   │
│   │                                                                         │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 🔄 Data Flow & Security

### 1. Device Registration Flow
```text
Operator → CLI/Web → REST API → CA Module → Certificate Generation
                  ↓             ↓
               Database ←── Broker Provisioning ←── ACL Update
                  ↓
            Credential Delivery → Secure ZIP + Download Link
```

### 2. Certificate Lifecycle
```text
Generate Keypair → Sign Certificate → Store Metadata → Package Credentials
                                   ↓
                             Update ACL Rules
                                   ↓
                          Device Manufacturing
                                   ↓
                            Production Deployment
                                   ↓
                      Revocation (if needed) → CRL Update
```

### 3. Security Boundaries

| Component | Security Features | Trust Level |
|-----------|------------------|-------------|
| **CA Module** | RSA 2048-bit keys, X.509v3 certificates, CRL management | 🔴 Critical |
| **REST API** | Input validation, UUID-based device IDs | 🟡 Trusted |
| **Database** | SQLite with foreign key constraints | 🟢 Internal |
| **Credential Delivery** | Password-protected ZIP, temporary links | 🟡 Trusted |
| **Broker Integration** | ACL-based topic restrictions, mTLS | 🔴 Critical |

## 🚀 Deployment Options

### Development
```bash
# Local SQLite + File-based storage
python -m src.secure_iot_onboarding.app
```

### Production
```bash
# PostgreSQL + Redis + Load Balancer
docker-compose up -d
```

## 📈 Scalability Considerations

- **Horizontal**: Multiple API instances behind load balancer
- **Database**: PostgreSQL cluster for production
- **Certificate Storage**: Distributed file system (S3, GCS)
- **Broker**: MQTT broker clustering with shared ACL store
- **Monitoring**: Certificate expiration alerts, audit logs

## 🔧 Configuration

Key configuration points:
- `DATABASE_URL`: Database connection string
- `CERT_VALIDITY_DAYS`: Certificate lifetime (default: 365)
- `CA_ROOT_PATH`: CA certificate and key location
- `BROKER_ACL_FILE`: Mosquitto ACL file path
- `DOWNLOAD_EXPIRY_MINUTES`: Credential link lifetime (default: 30)
