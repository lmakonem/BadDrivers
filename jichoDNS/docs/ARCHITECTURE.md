# JichoDNS Architecture

## System Overview

JichoDNS is a modular, scalable DNS threat intelligence platform designed for Africa-focused threat visibility. The architecture follows a microservices-inspired design with clear separation of concerns.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           JichoDNS Architecture                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   EXTERNAL DATA SOURCES                                                          │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │ Abuse.ch    │  │ PhishTank   │  │ RIPE Atlas  │  │   Shodan    │            │
│   │ • URLhaus   │  │             │  │             │  │             │            │
│   │ • ThreatFox │  │ AlienVault  │  │ VirusTotal  │  │   crt.sh    │            │
│   │ • Feodo     │  │    OTX      │  │             │  │             │            │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘            │
│          │                │                │                │                    │
│          ▼                ▼                ▼                ▼                    │
│   ┌─────────────────────────────────────────────────────────────────────┐       │
│   │                     INGESTION LAYER (Celery Workers)                 │       │
│   │                                                                      │       │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │       │
│   │  │ Feed Import  │  │ RIPE Atlas   │  │   Shodan     │              │       │
│   │  │   Workers    │  │  Scheduler   │  │  Enricher    │              │       │
│   │  │              │  │  & Collector │  │              │              │       │
│   │  └──────────────┘  └──────────────┘  └──────────────┘              │       │
│   │                                                                      │       │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │       │
│   │  │  DNSTwist    │  │ VirusTotal   │  │  AbuseIPDB   │              │       │
│   │  │  Scanner     │  │  Enricher    │  │  Checker     │              │       │
│   │  └──────────────┘  └──────────────┘  └──────────────┘              │       │
│   └────────────────────────────────┬────────────────────────────────────┘       │
│                                    │                                             │
│                                    ▼                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐       │
│   │                      PROCESSING LAYER                                │       │
│   │                                                                      │       │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │       │
│   │  │   Feature    │  │  ML Scoring  │  │   Pattern    │              │       │
│   │  │  Extraction  │  │ (Vertex AI)  │  │  Detection   │              │       │
│   │  └──────────────┘  └──────────────┘  └──────────────┘              │       │
│   │                                                                      │       │
│   │  ┌──────────────┐  ┌──────────────┐                                │       │
│   │  │   Region     │  │  Anomaly     │                                │       │
│   │  │ Aggregation  │  │  Detection   │                                │       │
│   │  └──────────────┘  └──────────────┘                                │       │
│   └────────────────────────────────┬────────────────────────────────────┘       │
│                                    │                                             │
│            ┌───────────────────────┼───────────────────────┐                    │
│            ▼                       ▼                       ▼                    │
│   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐              │
│   │ PostgreSQL  │         │ ClickHouse  │         │   Redis     │              │
│   │             │         │             │         │             │              │
│   │ • Indicators│         │ • DNS Events│         │ • Cache     │              │
│   │ • Scores    │         │ • Query Logs│         │ • Sessions  │              │
│   │ • Users     │         │ • Analytics │         │ • Task Queue│              │
│   │ • API Keys  │         │             │         │ • Rate Limit│              │
│   └──────┬──────┘         └──────┬──────┘         └─────────────┘              │
│          │                       │                                              │
│          └───────────┬───────────┘                                              │
│                      ▼                                                          │
│   ┌─────────────────────────────────────────────────────────────────────┐       │
│   │                        API LAYER (FastAPI)                           │       │
│   │                                                                      │       │
│   │  ┌─────────────────────────────────────────────────────────────┐    │       │
│   │  │                    API GATEWAY                               │    │       │
│   │  │  • JWT Authentication    • Rate Limiting                    │    │       │
│   │  │  • API Key Validation    • Quota Enforcement                │    │       │
│   │  └─────────────────────────────────────────────────────────────┘    │       │
│   │                                                                      │       │
│   │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐       │       │
│   │  │  PUBLIC    │ │  USER      │ │  PAID      │ │  ADMIN     │       │       │
│   │  │  /health   │ │  /enrich   │ │  /export   │ │  /users    │       │       │
│   │  │  /stats    │ │  /search   │ │  /hunt     │ │  /feeds    │       │       │
│   │  │  /map      │ │  /watchlist│ │  /webhooks │ │  /billing  │       │       │
│   │  └────────────┘ └────────────┘ └────────────┘ └────────────┘       │       │
│   └─────────────────────────────────────────────────────────────────────┘       │
│                                    │                                             │
│          ┌─────────────────────────┴─────────────────────────┐                  │
│          ▼                                                   ▼                  │
│   ┌─────────────────────────────┐       ┌─────────────────────────────┐         │
│   │      FRONTEND LAYER         │       │    EXTERNAL CONSUMERS       │         │
│   │      (Next.js 14)           │       │                             │         │
│   │                             │       │  • SIEM Integrations        │         │
│   │  • Interactive Map          │       │  • SOAR Playbooks           │         │
│   │  • Dashboard                │       │  • Custom Applications      │         │
│   │  • Admin Panel              │       │  • Research Tools           │         │
│   │  • Billing Portal           │       │                             │         │
│   └─────────────────────────────┘       └─────────────────────────────┘         │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Ingestion Layer

#### Feed Import Workers
- **Purpose**: Fetch and normalize data from threat intelligence feeds
- **Feeds**: Abuse.ch (URLhaus, ThreatFox, Feodo), PhishTank, AlienVault OTX
- **Schedule**: Every 5-15 minutes depending on feed
- **Output**: Normalized indicators in PostgreSQL

#### RIPE Atlas Scheduler & Collector
- **Purpose**: Create and manage DNS measurements from African probes
- **Targets**: Active indicators requiring measurement
- **Probe Selection**: African countries and ASNs
- **Schedule**: Continuous with rate limiting

#### Enrichment Workers
- **Shodan**: Infrastructure data, open ports, SSL certs
- **VirusTotal**: Reputation, detection counts
- **AbuseIPDB**: IP reputation scores
- **crt.sh**: Certificate transparency lookup
- **WHOIS**: Domain registration data

#### DNSTwist Scanner
- **Purpose**: Detect typosquatting domains
- **Targets**: Monitored African brands
- **Output**: Related lookalike domains with similarity scores

### 2. Processing Layer

#### Feature Extraction
- Domain string features (entropy, length, n-grams, TLD)
- DNS behavior features (RTT, availability, error rates)
- Infrastructure features (ASN diversity, IP rotation)
- Temporal features (age, activity patterns)

#### ML Scoring
- **Platform**: Vertex AI
- **Model**: HuggingFace-based classifier
- **Classes**: C2, Exfiltration, Phishing, Benign
- **Output**: Probability scores per class

#### Pattern Detection
- DGA pattern clustering
- Beaconing interval detection
- DNS tunneling signatures
- Fast-flux behavior

#### Region Aggregation
- Aggregate indicator scores by country
- Aggregate indicator scores by ASN
- Time-windowed summaries (15-min buckets)

### 3. Storage Layer

#### PostgreSQL
- **Role**: Primary transactional database
- **Data**: Indicators, scores, users, API keys, subscriptions
- **Extensions**: pg_trgm (text search), PostGIS (optional)

#### ClickHouse
- **Role**: Analytics and event storage
- **Data**: DNS events from RIPE Atlas, query logs
- **Partitioning**: By month
- **Retention**: 90 days for raw events

#### Redis
- **Role**: Caching, task queue, sessions
- **Use Cases**: 
  - Celery task broker
  - API response caching
  - Rate limit counters
  - Session storage

### 4. API Layer

#### Authentication
- **JWT**: For web dashboard users
- **API Keys**: For programmatic access
- **OAuth**: Google/GitHub login (optional)

#### Rate Limiting
- Per-user rate limits based on tier
- Redis-backed sliding window
- Quota tracking for billing

#### Endpoints by Access Level

| Level | Endpoints | Auth Required |
|-------|-----------|---------------|
| Public | /health, /stats, /map | None |
| User | /enrich, /search, /watchlist | JWT |
| Paid | /export, /hunt, /webhooks | API Key |
| Admin | /users, /feeds, /billing | JWT + Admin role |

### 5. Frontend Layer

#### Next.js Application
- **Pages**: Map, Dashboard, Indicators, Settings, Admin
- **State Management**: TanStack Query
- **Maps**: Mapbox GL JS
- **UI Components**: shadcn/ui

## Data Flow

### Indicator Ingestion Flow

```
Feed Source
    │
    ▼
Feed Importer (Celery)
    │
    ├─► Deduplicate
    │
    ├─► Normalize to common schema
    │
    ├─► Store in PostgreSQL
    │
    └─► Queue for enrichment
            │
            ▼
    Enrichment Workers
            │
            ├─► Shodan lookup
            ├─► VirusTotal check
            ├─► WHOIS lookup
            ├─► DNSTwist scan
            │
            ▼
    Feature Extraction
            │
            ▼
    ML Scoring (Vertex AI)
            │
            ▼
    Store scores in PostgreSQL
            │
            ▼
    Region Aggregation
            │
            ▼
    Update region_scores table
```

### API Request Flow

```
Client Request
    │
    ▼
Nginx (Reverse Proxy)
    │
    ▼
FastAPI App
    │
    ├─► Auth Middleware
    │       │
    │       ├─► Validate JWT/API Key
    │       └─► Check permissions
    │
    ├─► Rate Limit Middleware
    │       │
    │       └─► Check Redis counters
    │
    ▼
Route Handler
    │
    ├─► Cache check (Redis)
    │
    ├─► Database query
    │
    └─► Response
            │
            ▼
        Client
```

## Scalability Considerations

### Horizontal Scaling

| Component | Scaling Strategy |
|-----------|-----------------|
| API | Multiple instances behind load balancer |
| Workers | Add more Celery workers |
| PostgreSQL | Read replicas for queries |
| ClickHouse | Sharding for high-volume events |
| Redis | Redis Cluster for high availability |

### Performance Optimizations

- **Caching**: Redis cache for frequently accessed data
- **Batch Processing**: Bulk inserts for events
- **Connection Pooling**: PgBouncer for PostgreSQL
- **Async I/O**: FastAPI async endpoints

## Security Considerations

### Data Security
- Encrypted connections (TLS) for all services
- API key hashing (SHA-256)
- Secrets management via environment variables

### Access Control
- Role-based access control (RBAC)
- API key scopes
- IP whitelist option for enterprise

### Input Validation
- Pydantic schemas for all inputs
- SQL injection prevention via ORM
- Rate limiting to prevent abuse

## Monitoring & Observability

### Metrics (Prometheus)
- Request latency
- Error rates
- Queue depths
- Database connections

### Logging (Loki)
- Structured JSON logs
- Request tracing
- Error tracking

### Dashboards (Grafana)
- API performance
- Worker status
- Feed freshness
- System health

## Deployment Options

### Development
- Docker Compose with all services
- Hot reload for backend/frontend
- Local PostgreSQL and Redis

### Production
- Docker Swarm or Kubernetes
- Managed PostgreSQL (or self-hosted)
- Redis cluster
- Nginx reverse proxy with SSL
