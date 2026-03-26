# JichoDNS Deployment Guide

## Overview

This guide covers deployment of JichoDNS to your local datacenter infrastructure.

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32 GB |
| Storage | 100 GB SSD | 500 GB NVMe |
| Network | 100 Mbps | 1 Gbps |

### Software Requirements

- Docker 24.0+
- Docker Compose 2.20+
- Git
- SSL certificate (Let's Encrypt or commercial)

### External Services

- RIPE Atlas API key
- Shodan API key (Membership)
- Google Cloud service account (Vertex AI)
- Mapbox access token
- Stripe account (for payments)
- Paystack account (for African payments)

---

## Development Setup

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/jichoDNS.git
cd jichoDNS
```

### 2. Environment Configuration

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```bash
# =============================================================================
# JichoDNS Environment Configuration
# =============================================================================

# -----------------------------------------------------------------------------
# Application
# -----------------------------------------------------------------------------
APP_ENV=development
APP_DEBUG=true
APP_SECRET_KEY=your-secret-key-change-in-production

# -----------------------------------------------------------------------------
# Database - PostgreSQL
# -----------------------------------------------------------------------------
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=jichodns
POSTGRES_USER=jichodns
POSTGRES_PASSWORD=secure_password_here

# -----------------------------------------------------------------------------
# Database - ClickHouse
# -----------------------------------------------------------------------------
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_PORT=9000
CLICKHOUSE_DB=jichodns
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=

# -----------------------------------------------------------------------------
# Cache & Queue - Redis
# -----------------------------------------------------------------------------
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=

# -----------------------------------------------------------------------------
# RIPE Atlas
# -----------------------------------------------------------------------------
RIPE_ATLAS_API_KEY=your_ripe_atlas_api_key
RIPE_ATLAS_PROBE_COUNTRIES=KE,ZA,NG,EG,GH,TZ,UG,ET,MA,SN

# -----------------------------------------------------------------------------
# Shodan
# -----------------------------------------------------------------------------
SHODAN_API_KEY=your_shodan_api_key

# -----------------------------------------------------------------------------
# Google Cloud (Vertex AI)
# -----------------------------------------------------------------------------
GOOGLE_APPLICATION_CREDENTIALS=/app/credentials/gcp-service-account.json
VERTEX_AI_PROJECT=your-gcp-project
VERTEX_AI_LOCATION=us-central1
VERTEX_AI_ENDPOINT=your-endpoint-id

# -----------------------------------------------------------------------------
# Threat Intelligence APIs
# -----------------------------------------------------------------------------
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_alienvault_otx_key
PHISHTANK_API_KEY=your_phishtank_api_key

# -----------------------------------------------------------------------------
# Frontend
# -----------------------------------------------------------------------------
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_MAPBOX_TOKEN=your_mapbox_access_token

# -----------------------------------------------------------------------------
# Payments
# -----------------------------------------------------------------------------
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_PUBLISHABLE_KEY=pk_test_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

PAYSTACK_SECRET_KEY=sk_test_xxx
PAYSTACK_PUBLIC_KEY=pk_test_xxx
```

### 3. Start Development Stack

```bash
docker-compose up -d
```

### 4. Initialize Database

```bash
# Run PostgreSQL migrations
docker-compose exec backend alembic upgrade head

# Initialize ClickHouse tables
docker-compose exec clickhouse clickhouse-client \
  --query="$(cat infra/scripts/setup_clickhouse.sql)"
```

### 5. Create Admin User

```bash
docker-compose exec backend python -m app.cli create-admin \
  --email admin@example.com \
  --password your_secure_password
```

### 6. Access Services

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Grafana | http://localhost:3001 |

---

## Production Deployment

### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create application directory
sudo mkdir -p /opt/jichodns
sudo chown $USER:$USER /opt/jichodns
```

### 2. Clone and Configure

```bash
cd /opt/jichodns
git clone https://github.com/yourusername/jichoDNS.git .
cp .env.example .env.production
```

Edit `.env.production`:
```bash
APP_ENV=production
APP_DEBUG=false
APP_SECRET_KEY=$(openssl rand -hex 32)

# Use strong passwords
POSTGRES_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 16)

# Production API URLs
NEXT_PUBLIC_API_URL=https://api.jichodns.io
```

### 3. SSL Certificates

**Option A: Let's Encrypt (Recommended)**

```bash
# Install certbot
sudo apt install certbot -y

# Generate certificates
sudo certbot certonly --standalone \
  -d jichodns.io \
  -d api.jichodns.io \
  -d www.jichodns.io

# Copy to Docker-accessible location
sudo cp /etc/letsencrypt/live/jichodns.io/fullchain.pem /opt/jichodns/infra/certs/
sudo cp /etc/letsencrypt/live/jichodns.io/privkey.pem /opt/jichodns/infra/certs/
```

**Option B: Commercial Certificate**

Place your certificate files in `/opt/jichodns/infra/certs/`:
- `fullchain.pem`
- `privkey.pem`

### 4. Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./infra/nginx/nginx.prod.conf:/etc/nginx/nginx.conf:ro
      - ./infra/certs:/etc/nginx/certs:ro
    depends_on:
      - frontend
      - backend
    restart: always

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.prod
    environment:
      - NODE_ENV=production
    env_file:
      - .env.production
    restart: always

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    env_file:
      - .env.production
    volumes:
      - ./credentials:/app/credentials:ro
    depends_on:
      - postgres
      - redis
      - clickhouse
    restart: always

  celery-worker:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    command: celery -A app.workers.celery_app worker -l info -c 4
    env_file:
      - .env.production
    volumes:
      - ./credentials:/app/credentials:ro
    depends_on:
      - postgres
      - redis
    restart: always

  celery-beat:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    command: celery -A app.workers.celery_app beat -l info
    env_file:
      - .env.production
    depends_on:
      - postgres
      - redis
    restart: always

  postgres:
    image: postgres:15-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
    env_file:
      - .env.production
    restart: always

  clickhouse:
    image: clickhouse/clickhouse-server:latest
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    restart: always

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    restart: always

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./infra/prometheus:/etc/prometheus:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=30d'
    restart: always

  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana_data:/var/lib/grafana
      - ./infra/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_SERVER_ROOT_URL=https://grafana.jichodns.io
    restart: always

volumes:
  postgres_data:
  clickhouse_data:
  redis_data:
  prometheus_data:
  grafana_data:
```

### 5. Nginx Configuration

Create `infra/nginx/nginx.prod.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=general:10m rate=30r/s;

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name jichodns.io www.jichodns.io api.jichodns.io;
        return 301 https://$server_name$request_uri;
    }

    # Main website
    server {
        listen 443 ssl http2;
        server_name jichodns.io www.jichodns.io;

        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;

        limit_req zone=general burst=50 nodelay;

        location / {
            proxy_pass http://frontend:3000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }
    }

    # API
    server {
        listen 443 ssl http2;
        server_name api.jichodns.io;

        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;

        limit_req zone=api burst=20 nodelay;

        location / {
            proxy_pass http://backend:8000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # CORS headers (if needed)
            add_header Access-Control-Allow-Origin "https://jichodns.io" always;
            add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
        }
    }
}
```

### 6. Start Production Stack

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### 7. Initialize Production Database

```bash
docker-compose -f docker-compose.prod.yml exec backend alembic upgrade head
docker-compose -f docker-compose.prod.yml exec backend python -m app.cli create-admin \
  --email admin@jichodns.io \
  --password your_secure_password
```

---

## Monitoring

### Prometheus Metrics

The backend exposes metrics at `/metrics`:

- `jichodns_indicators_total` - Total indicators by type
- `jichodns_api_requests_total` - API requests by endpoint
- `jichodns_feed_imports_total` - Feed import counts
- `jichodns_atlas_measurements_total` - RIPE Atlas measurements
- `jichodns_ml_scoring_duration_seconds` - ML scoring latency

### Grafana Dashboards

Pre-built dashboards for:
- API Performance
- Feed Health
- Atlas Coverage
- System Resources

Access at: `https://grafana.jichodns.io`

### Alerting

Configure alerts in Prometheus for:
- API error rate > 5%
- Feed import failures
- Database connection issues
- Disk space < 20%

---

## Backup Strategy

### PostgreSQL

```bash
# Daily backup
docker-compose exec postgres pg_dump -U jichodns jichodns | gzip > backup_$(date +%Y%m%d).sql.gz

# Restore
gunzip -c backup_20260316.sql.gz | docker-compose exec -T postgres psql -U jichodns jichodns
```

### ClickHouse

```bash
# Backup
docker-compose exec clickhouse clickhouse-client \
  --query="BACKUP DATABASE jichodns TO Disk('backups', 'jichodns_$(date +%Y%m%d)')"
```

### Automated Backups

Add to crontab:
```cron
0 2 * * * /opt/jichodns/scripts/backup.sh >> /var/log/jichodns-backup.log 2>&1
```

---

## Scaling Considerations

### Horizontal Scaling

| Component | Scaling Method |
|-----------|---------------|
| API | Multiple instances behind Nginx |
| Celery Workers | Add more workers |
| PostgreSQL | Read replicas |
| ClickHouse | Sharding |

### Recommended Production Setup

```
Load Balancer (Nginx)
        │
        ├── Frontend (2 instances)
        │
        ├── API (3 instances)
        │
        └── Workers
                ├── Feed Importers (2)
                ├── Atlas Scheduler (1)
                ├── Enrichment (4)
                └── Scoring (2)
```

---

## Troubleshooting

### Common Issues

**API not responding:**
```bash
docker-compose logs backend
docker-compose restart backend
```

**Database connection errors:**
```bash
docker-compose exec postgres pg_isready
docker-compose restart postgres
```

**Feed imports failing:**
```bash
docker-compose logs celery-worker
# Check API keys in .env
```

**High memory usage:**
```bash
docker stats
# Adjust worker concurrency
docker-compose exec celery-worker celery -A app.workers.celery_app inspect active
```

### Log Locations

| Service | Log Location |
|---------|--------------|
| Nginx | `/var/log/nginx/` |
| Backend | `docker-compose logs backend` |
| Workers | `docker-compose logs celery-worker` |
| PostgreSQL | `docker-compose logs postgres` |

---

## Security Checklist

- [ ] Change all default passwords
- [ ] Enable firewall (ufw/iptables)
- [ ] Configure SSL/TLS
- [ ] Set up fail2ban
- [ ] Enable audit logging
- [ ] Regular security updates
- [ ] API key rotation policy
- [ ] Backup encryption
- [ ] Network segmentation
- [ ] Intrusion detection
