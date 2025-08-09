# Production Deployment Guide

## 📋 **Overview**

This guide provides comprehensive instructions for deploying the Secure IoT Device Onboarding Portal in production environments. It covers infrastructure requirements, security hardening, monitoring, and operational considerations.

## 🏗️ **Infrastructure Architecture**

### Recommended Production Architecture

```
                    ┌─────────────────┐
                    │   Load Balancer │
                    │   (HTTPS/TLS)   │
                    └─────────────────┘
                             │
                    ┌─────────────────┐
                    │   Web Gateway   │
                    │  (Rate Limiting) │
                    └─────────────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │   App Server │ │   App Server │ │   App Server │
    │   Instance 1 │ │   Instance 2 │ │   Instance 3 │
    └──────────────┘ └──────────────┘ └──────────────┘
            │                │                │
            └────────────────┼────────────────┘
                             │
                    ┌─────────────────┐
                    │   Database      │
                    │   (PostgreSQL)  │
                    └─────────────────┘
                             │
                    ┌─────────────────┐
                    │   HSM/KMS       │
                    │   (CA Keys)     │
                    └─────────────────┘
```

### Component Specifications

#### Load Balancer
- **Purpose**: HTTPS termination, traffic distribution, health checking
- **Recommended**: AWS Application Load Balancer, NGINX, HAProxy
- **Configuration**: SSL/TLS termination, health checks, rate limiting

#### Application Servers
- **Purpose**: Run IoT onboarding application instances
- **Specifications**: 
  - CPU: 4+ cores
  - RAM: 8+ GB
  - Storage: 100+ GB SSD
  - OS: Ubuntu 20.04 LTS or RHEL 8

#### Database
- **Purpose**: Store device metadata and certificate information
- **Recommended**: PostgreSQL 13+, MySQL 8.0+
- **Specifications**:
  - CPU: 8+ cores
  - RAM: 16+ GB
  - Storage: 500+ GB SSD with encryption
  - Backup: Automated daily backups

#### HSM/KMS
- **Purpose**: Secure CA private key storage
- **Options**: AWS KMS, Azure Key Vault, Hardware Security Module
- **Requirements**: FIPS 140-2 Level 3 compliance

## 🔒 **Security Hardening**

### Operating System Security

#### System Updates
```bash
# Automated security updates (Ubuntu)
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
systemctl enable unattended-upgrades

# Security-only updates (RHEL)
yum-config-manager --enable rhel-8-for-x86_64-baseos-rpms
yum update --security -y
```

#### User Account Security
```bash
# Disable root login
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Create service account
useradd -r -s /bin/false iot-onboarding
usermod -L iot-onboarding  # Lock password

# SSH key-only authentication
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
```

#### Firewall Configuration
```bash
# UFW (Ubuntu Firewall) configuration
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 443/tcp   # HTTPS
ufw allow 8883/tcp  # MQTT over TLS
ufw enable

# iptables alternative
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 8883 -j ACCEPT
```

### Application Security

#### Environment Configuration
```bash
# .env.production
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-256-bit-secret-key-here
DATABASE_URL=postgresql://user:pass@db-host:5432/iot_onboarding
CA_PRIVATE_KEY_ID=arn:aws:kms:region:account:key/key-id
MQTT_BROKER_HOST=broker.example.com
MQTT_BROKER_PORT=8883
LOG_LEVEL=INFO
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS_PER_MINUTE=60
```

#### TLS Configuration
```python
# app.py security configuration
from flask_talisman import Talisman

app = Flask(__name__)

# Security headers
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
    }
)

# HTTPS only cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)
```

### Database Security

#### PostgreSQL Configuration
```sql
-- Create dedicated database and user
CREATE DATABASE iot_onboarding;
CREATE USER iot_app WITH ENCRYPTED PASSWORD 'secure-password';
GRANT CONNECT ON DATABASE iot_onboarding TO iot_app;
GRANT USAGE ON SCHEMA public TO iot_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO iot_app;

-- Enable SSL connections only
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_cert_file = '/path/to/server.crt';
ALTER SYSTEM SET ssl_key_file = '/path/to/server.key';
ALTER SYSTEM SET ssl_ca_file = '/path/to/ca.crt';
```

#### Database Encryption
```bash
# Enable encryption at rest (PostgreSQL with LUKS)
cryptsetup luksFormat /dev/xvdf
cryptsetup luksOpen /dev/xvdf postgres_data
mkfs.ext4 /dev/mapper/postgres_data
mount /dev/mapper/postgres_data /var/lib/postgresql/data
```

## 📊 **Monitoring and Observability**

### Application Monitoring

#### Health Check Endpoint
```python
from flask import jsonify
import time

@app.route('/health')
def health_check():
    """Comprehensive health check endpoint"""
    health_status = {
        'status': 'healthy',
        'timestamp': time.time(),
        'version': app.config.get('VERSION', 'unknown'),
        'checks': {}
    }
    
    # Database connectivity
    try:
        db.session.execute('SELECT 1')
        health_status['checks']['database'] = 'healthy'
    except Exception as e:
        health_status['checks']['database'] = 'unhealthy'
        health_status['status'] = 'unhealthy'
    
    # CA availability
    try:
        from . import ca
        ca.ensure_ca_root()
        health_status['checks']['certificate_authority'] = 'healthy'
    except Exception as e:
        health_status['checks']['certificate_authority'] = 'unhealthy'
        health_status['status'] = 'unhealthy'
    
    # MQTT broker connectivity
    try:
        import paho.mqtt.client as mqtt
        client = mqtt.Client()
        client.connect(app.config['MQTT_BROKER_HOST'], 
                      app.config['MQTT_BROKER_PORT'], 60)
        client.disconnect()
        health_status['checks']['mqtt_broker'] = 'healthy'
    except Exception as e:
        health_status['checks']['mqtt_broker'] = 'unhealthy'
        health_status['status'] = 'degraded'
    
    return jsonify(health_status), 200 if health_status['status'] == 'healthy' else 503
```

#### Metrics Collection
```python
from prometheus_client import Counter, Histogram, Gauge, generate_latest

# Define metrics
device_registrations = Counter('device_registrations_total', 
                              'Total device registrations')
certificate_issuance_time = Histogram('certificate_issuance_seconds',
                                     'Time spent issuing certificates')
active_devices = Gauge('active_devices_total',
                      'Number of active devices')

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest()

def record_device_registration():
    device_registrations.inc()
    active_devices.set(count_active_devices())

@certificate_issuance_time.time()
def issue_certificate(device_id):
    # Certificate issuance logic
    pass
```

### Infrastructure Monitoring

#### System Metrics
```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=secure-password
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning

  node_exporter:
    image: prom/node-exporter:latest
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.ignored-mount-points'

volumes:
  prometheus_data:
  grafana_data:
```

#### Log Management
```python
import logging
import json
from logging.handlers import RotatingFileHandler

# Structured logging configuration
class StructuredLogger:
    def __init__(self):
        self.logger = logging.getLogger('iot_onboarding')
        self.logger.setLevel(logging.INFO)
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            '/var/log/iot-onboarding/app.log',
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        
        # JSON formatter
        file_handler.setFormatter(self.JsonFormatter())
        self.logger.addHandler(file_handler)
    
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_entry = {
                'timestamp': self.formatTime(record),
                'level': record.levelname,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno
            }
            
            if hasattr(record, 'device_id'):
                log_entry['device_id'] = record.device_id
            if hasattr(record, 'user_ip'):
                log_entry['user_ip'] = record.user_ip
                
            return json.dumps(log_entry)

# Usage
logger = StructuredLogger().logger

def register_device(device_data, request_ip):
    extra = {'device_id': device_data.get('name'), 'user_ip': request_ip}
    logger.info('Device registration started', extra=extra)
    
    try:
        # Registration logic
        logger.info('Device registration completed', extra=extra)
    except Exception as e:
        logger.error(f'Device registration failed: {str(e)}', extra=extra)
        raise
```

## 🚀 **Deployment Automation**

### Docker Deployment

#### Production Dockerfile
```dockerfile
# Dockerfile.production
FROM python:3.11-slim-bullseye

# Security updates
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r iot && useradd -r -g iot iot

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ src/
COPY pyproject.toml .

# Install application
RUN pip install -e .

# Change ownership to non-root user
RUN chown -R iot:iot /app

# Switch to non-root user
USER iot

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Expose port
EXPOSE 5000

# Start application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", \
     "--worker-class", "gevent", "--worker-connections", "1000", \
     "--max-requests", "1000", "--max-requests-jitter", "100", \
     "--timeout", "30", "--keep-alive", "5", \
     "src.secure_iot_onboarding.app:app"]
```

#### Docker Compose Production
```yaml
# docker-compose.production.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.production
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://iot_user:${DB_PASSWORD}@db:5432/iot_onboarding
    depends_on:
      - db
      - redis
    networks:
      - iot_network
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G

  db:
    image: postgres:13-alpine
    environment:
      - POSTGRES_DB=iot_onboarding
      - POSTGRES_USER=iot_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - iot_network
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G

  redis:
    image: redis:6-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    networks:
      - iot_network

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app
    networks:
      - iot_network

networks:
  iot_network:
    driver: overlay
    attachable: true

volumes:
  postgres_data:
```

### Kubernetes Deployment

#### Deployment Manifest
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iot-onboarding
  labels:
    app: iot-onboarding
spec:
  replicas: 3
  selector:
    matchLabels:
      app: iot-onboarding
  template:
    metadata:
      labels:
        app: iot-onboarding
    spec:
      serviceAccountName: iot-onboarding
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: app
        image: iot-onboarding:latest
        ports:
        - containerPort: 5000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-secret
              key: url
        - name: CA_PRIVATE_KEY_ID
          valueFrom:
            secretKeyRef:
              name: ca-secret
              key: key-id
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1"
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 10
          periodSeconds: 5
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
---
apiVersion: v1
kind: Service
metadata:
  name: iot-onboarding-service
spec:
  selector:
    app: iot-onboarding
  ports:
  - protocol: TCP
    port: 80
    targetPort: 5000
  type: ClusterIP
```

### CI/CD Pipeline

#### GitHub Actions Workflow
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -e .
    
    - name: Run tests
      run: pytest tests/ --cov=src --cov-report=xml
    
    - name: Security scan
      run: |
        pip install bandit safety
        bandit -r src/
        safety check

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Build Docker image
      run: |
        docker build -f Dockerfile.production -t iot-onboarding:${{ github.sha }} .
        docker tag iot-onboarding:${{ github.sha }} iot-onboarding:latest
    
    - name: Security scan image
      run: |
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
          aquasec/trivy:latest image iot-onboarding:${{ github.sha }}

  deploy:
    needs: [test, build]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
    - name: Deploy to production
      run: |
        # Deploy to Kubernetes/Docker Swarm/Cloud platform
        echo "Deploying to production..."
```

## 🔧 **Operational Procedures**

### Backup and Recovery

#### Database Backup
```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/backups/postgres"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="iot_onboarding_${TIMESTAMP}.sql.gz"

# Create backup directory
mkdir -p $BACKUP_DIR

# Perform backup
pg_dump -h localhost -U iot_user -d iot_onboarding | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"

# Encrypt backup
gpg --encrypt --recipient backup@company.com "${BACKUP_DIR}/${BACKUP_FILE}"
rm "${BACKUP_DIR}/${BACKUP_FILE}"

# Upload to S3 (optional)
aws s3 cp "${BACKUP_DIR}/${BACKUP_FILE}.gpg" s3://company-backups/iot-onboarding/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.gpg" -mtime +30 -delete

echo "Backup completed: ${BACKUP_FILE}.gpg"
```

#### Certificate Authority Backup
```bash
#!/bin/bash
# backup-ca.sh

CA_DIR="/etc/ssl/ca"
BACKUP_DIR="/backups/ca"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create encrypted backup
tar -czf - $CA_DIR | gpg --encrypt --recipient ca-backup@company.com > \
  "${BACKUP_DIR}/ca_backup_${TIMESTAMP}.tar.gz.gpg"

# Store in secure location
aws s3 cp "${BACKUP_DIR}/ca_backup_${TIMESTAMP}.tar.gz.gpg" \
  s3://company-secure-backups/ca/ --storage-class GLACIER

echo "CA backup completed: ca_backup_${TIMESTAMP}.tar.gz.gpg"
```

### Certificate Rotation

#### Automated Certificate Renewal
```python
#!/usr/bin/env python3
# certificate-renewal.py

import sys
from datetime import datetime, timedelta
from src.secure_iot_onboarding import db, ca

def renew_expiring_certificates():
    """Renew certificates expiring within 30 days"""
    
    # Find certificates expiring soon
    thirty_days = datetime.utcnow() + timedelta(days=30)
    expiring_certs = db.get_certificates_expiring_before(thirty_days)
    
    for cert in expiring_certs:
        try:
            device = db.get_device(cert.device_id)
            if device.status != 'active':
                continue
                
            # Generate new certificate
            new_cert = ca.renew_device_certificate(device.id)
            
            # Update database
            db.update_certificate(cert.id, new_cert)
            
            # Send notification to device management system
            send_renewal_notification(device.id, new_cert)
            
            print(f"Renewed certificate for device {device.id}")
            
        except Exception as e:
            print(f"Failed to renew certificate for device {cert.device_id}: {e}")
            continue

def send_renewal_notification(device_id, certificate):
    """Send certificate renewal notification"""
    # Implementation depends on your notification system
    pass

if __name__ == "__main__":
    renew_expiring_certificates()
```

### Incident Response

#### Security Incident Checklist
```bash
#!/bin/bash
# incident-response.sh

echo "=== IoT Onboarding Security Incident Response ==="
echo "1. Immediate Actions:"
echo "   - [ ] Identify affected devices"
echo "   - [ ] Revoke compromised certificates"
echo "   - [ ] Block suspicious IP addresses"
echo "   - [ ] Preserve evidence"

echo ""
echo "2. Certificate Revocation:"
read -p "Enter device ID to revoke: " DEVICE_ID
if [ ! -z "$DEVICE_ID" ]; then
    python3 -c "
from src.secure_iot_onboarding.cli import revoke
revoke('$DEVICE_ID')
"
    echo "Certificate revoked for device: $DEVICE_ID"
fi

echo ""
echo "3. Evidence Collection:"
echo "   - Collecting system logs..."
journalctl -u iot-onboarding --since="1 hour ago" > incident_logs_$(date +%Y%m%d_%H%M%S).log

echo "   - Collecting application logs..."
cp /var/log/iot-onboarding/app.log incident_app_logs_$(date +%Y%m%d_%H%M%S).log

echo ""
echo "4. Communication:"
echo "   - [ ] Notify security team"
echo "   - [ ] Update incident tracking system"
echo "   - [ ] Document response actions"

echo ""
echo "Incident response actions completed."
```

## 📈 **Performance Optimization**

### Application Optimization

#### Database Query Optimization
```python
# Optimized database queries
from sqlalchemy import func
from sqlalchemy.orm import joinedload

def get_active_devices_optimized():
    """Optimized query for active devices"""
    return db.session.query(Device)\
        .options(joinedload(Device.certificates))\
        .filter(Device.status == 'active')\
        .filter(Device.certificates.any(
            Certificate.expires_at > datetime.utcnow(),
            Certificate.revoked == False
        ))\
        .all()

def get_device_statistics():
    """Get device statistics efficiently"""
    stats = db.session.query(
        Device.type,
        func.count(Device.id).label('count')
    ).filter(Device.status == 'active')\
     .group_by(Device.type)\
     .all()
    
    return {stat.type: stat.count for stat in stats}
```

#### Caching Strategy
```python
from flask_caching import Cache
import redis

# Configure Redis cache
cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/0',
    'CACHE_DEFAULT_TIMEOUT': 300
})

@cache.memoize(timeout=3600)  # Cache for 1 hour
def get_ca_certificate():
    """Cache CA certificate to reduce disk I/O"""
    return ca.get_ca_certificate()

@cache.memoize(timeout=300)   # Cache for 5 minutes
def get_device_count_by_type():
    """Cache device statistics"""
    return get_device_statistics()

def invalidate_device_cache(device_id):
    """Invalidate cache when device is updated"""
    cache.delete_memoized(get_device_count_by_type)
    cache.delete(f"device_{device_id}")
```

### Infrastructure Scaling

#### Horizontal Scaling Configuration
```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: iot-onboarding-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: iot-onboarding
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

---

This production deployment guide provides the foundation for running the IoT onboarding system securely and reliably in production environments. Regular review and updates of these procedures ensure continued security and operational excellence.
