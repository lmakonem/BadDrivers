# JichoDNS Development Roadmap

## Overview

This document outlines the phased implementation plan for JichoDNS, an Africa-focused DNS threat visibility platform.

**Target Timeline:** 4-6 weeks for MVP

---

## Phase 1: Foundation (Week 1)

### Goals
- Set up development environment
- Establish project structure
- Deploy core infrastructure

### Tasks

| Task | Priority | Est. Hours | Owner |
|------|----------|------------|-------|
| Initialize Git repository with structure | P0 | 2h | - |
| Create Docker Compose for development | P0 | 4h | - |
| Set up PostgreSQL with initial schema | P0 | 4h | - |
| Set up ClickHouse for events | P0 | 3h | - |
| Set up Redis for cache/queue | P0 | 2h | - |
| FastAPI project scaffolding | P0 | 4h | - |
| Next.js project scaffolding | P0 | 4h | - |
| Basic authentication (JWT) | P1 | 6h | - |
| Environment configuration | P0 | 2h | - |
| GitHub Actions CI/CD | P1 | 4h | - |

### Deliverables
- [ ] Running Docker Compose stack
- [ ] Database schemas applied
- [ ] API responding at localhost:8000
- [ ] Frontend at localhost:3000
- [ ] CI pipeline running tests

### Directory Structure Created
```
jichoDNS/
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   └── api/v1/
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/app/
│   ├── Dockerfile
│   └── package.json
└── infra/
    └── docker/
```

---

## Phase 2: Data Ingestion (Week 2)

### Goals
- Implement indicator management
- Set up threat feed importers
- Build deduplication pipeline

### Tasks

| Task | Priority | Est. Hours | Owner |
|------|----------|------------|-------|
| Indicator CRUD API | P0 | 6h | - |
| Indicator Pydantic schemas | P0 | 3h | - |
| Celery worker setup | P0 | 4h | - |
| Abuse.ch URLhaus importer | P0 | 4h | - |
| Abuse.ch ThreatFox importer | P0 | 4h | - |
| Abuse.ch Feodo Tracker importer | P0 | 3h | - |
| PhishTank importer | P0 | 4h | - |
| AlienVault OTX importer | P1 | 4h | - |
| Feed aggregator/deduplicator | P0 | 6h | - |
| Celery Beat schedule config | P0 | 3h | - |
| Basic indicator list UI | P1 | 6h | - |

### Deliverables
- [ ] Indicators flowing from 5+ feeds
- [ ] Deduplication working
- [ ] Scheduled imports every 5-15 minutes
- [ ] Basic indicator table in UI

### Feed Integration Order
1. URLhaus (high volume, good quality)
2. ThreatFox (malware family attribution)
3. Feodo Tracker (banking trojans)
4. PhishTank (verified phishing)
5. OTX (community IOCs)

---

## Phase 3: RIPE Atlas Integration (Week 3)

### Goals
- Active DNS measurements from African probes
- Result collection and normalization
- Probe metadata caching

### Tasks

| Task | Priority | Est. Hours | Owner |
|------|----------|------------|-------|
| RIPE Atlas client wrapper | P0 | 4h | - |
| Measurement scheduler worker | P0 | 8h | - |
| Probe selection (African ASNs) | P0 | 4h | - |
| Result collector worker | P0 | 6h | - |
| Event normalization to ClickHouse | P0 | 6h | - |
| Probe metadata cache (PostgreSQL) | P1 | 4h | - |
| Credit monitoring/alerts | P1 | 3h | - |
| Measurement status API | P1 | 3h | - |

### Deliverables
- [ ] DNS measurements created for active indicators
- [ ] Results flowing to ClickHouse
- [ ] African probe coverage map
- [ ] Credit usage dashboard

### Measurement Strategy
```yaml
DNS Measurements:
  query_types: [A, AAAA, TXT]
  protocol: UDP
  probe_selection:
    type: country
    countries: [KE, ZA, NG, EG, GH, TZ, UG, ET, MA, SN]
    probes_per_country: 5
  interval: 900  # 15 minutes
  
Priority Indicators:
  - Newly seen (< 24h old)
  - High confidence threats
  - Active C2 domains
```

---

## Phase 4: Analysis & ML (Week 4)

### Goals
- Feature extraction pipeline
- ML scoring integration
- Pattern detection

### Tasks

| Task | Priority | Est. Hours | Owner |
|------|----------|------------|-------|
| Domain string features | P0 | 4h | - |
| - Entropy calculation | - | - | - |
| - Length, label count, TLD | - | - | - |
| - N-gram features | - | - | - |
| DNS behavior features | P0 | 6h | - |
| - RTT statistics | - | - | - |
| - Availability metrics | - | - | - |
| - Error rate analysis | - | - | - |
| Infrastructure features | P1 | 4h | - |
| - IP rotation detection | - | - | - |
| - ASN diversity | - | - | - |
| Feature builder Celery job | P0 | 4h | - |
| Vertex AI client | P0 | 4h | - |
| Scoring worker | P0 | 6h | - |
| Region score aggregation | P0 | 6h | - |
| Query pattern analysis | P1 | 6h | - |
| - TXT ratio anomaly | - | - | - |
| - Subdomain entropy | - | - | - |
| DNSTwist integration | P1 | 4h | - |
| Shodan enrichment worker | P1 | 4h | - |

### Deliverables
- [ ] Features computed for all indicators
- [ ] ML scores from Vertex AI
- [ ] Region-level risk aggregates
- [ ] Typosquatting detection for African brands
- [ ] Query pattern anomalies flagged

### Feature Vector (Example)
```python
{
    # Domain string features
    "domain_length": 24,
    "label_count": 3,
    "entropy": 3.8,
    "digit_ratio": 0.12,
    "has_hyphen": True,
    "tld": "xyz",
    
    # DNS behavior features
    "resolution_rate": 0.95,
    "avg_rtt_ms": 45.2,
    "rtt_stddev": 12.3,
    "nxdomain_rate": 0.02,
    
    # Infrastructure features
    "unique_ips_24h": 4,
    "unique_asns": 2,
    "avg_ttl": 60,
    
    # Temporal features
    "age_hours": 8,
    "first_seen_feed_hours": 6
}
```

---

## Phase 5: Frontend & Visualization (Week 5)

### Goals
- Interactive Africa map
- Dashboard components
- Indicator details view

### Tasks

| Task | Priority | Est. Hours | Owner |
|------|----------|------------|-------|
| Mapbox GL JS setup | P0 | 4h | - |
| Africa GeoJSON data | P0 | 2h | - |
| Choropleth layer (risk) | P0 | 6h | - |
| Time range selector | P0 | 4h | - |
| Threat type toggle (C2/Exfil/Phishing) | P0 | 4h | - |
| Region hover tooltips | P1 | 3h | - |
| Region click → detail panel | P0 | 6h | - |
| Hotspots panel | P0 | 4h | - |
| Indicator table with filters | P0 | 6h | - |
| Indicator detail view | P0 | 8h | - |
| - Multi-source enrichment | - | - | - |
| - Query pattern visualization | - | - | - |
| - Infrastructure timeline | - | - | - |
| NOD dashboard (< 20h domains) | P0 | 6h | - |
| Search functionality | P1 | 4h | - |
| Color scales & legend | P1 | 3h | - |

### Deliverables
- [ ] Interactive Africa threat map
- [ ] Drill-down to country/ASN
- [ ] Indicator enrichment view
- [ ] Newly Observed Domains dashboard
- [ ] Time-based filtering

### Map Features (Inspired by ISC Atlas Vis)
```
Visualization Layers:
1. Choropleth by threat risk (color intensity)
2. Probe coverage markers
3. Active measurement indicators
4. Hotspot clusters

Interactions:
- Zoom: Mouse scroll, buttons
- Pan: Click and drag
- Hover: Quick stats tooltip
- Click: Open detail panel
- Filter: By threat type, time range
```

---

## Phase 6: Polish & Launch (Week 6)

### Goals
- Production deployment
- Payment integration
- Documentation

### Tasks

| Task | Priority | Est. Hours | Owner |
|------|----------|------------|-------|
| Error handling in workers | P0 | 4h | - |
| Retry logic with backoff | P0 | 3h | - |
| API rate limiting | P0 | 3h | - |
| API key management UI | P1 | 4h | - |
| Stripe integration | P1 | 6h | - |
| Paystack integration | P1 | 4h | - |
| Usage metering | P1 | 4h | - |
| Prometheus metrics | P1 | 4h | - |
| Grafana dashboards | P2 | 4h | - |
| Production Docker Compose | P0 | 4h | - |
| Nginx configuration | P0 | 3h | - |
| SSL/TLS setup | P0 | 2h | - |
| API documentation (OpenAPI) | P1 | 4h | - |
| User guide | P2 | 4h | - |
| Security review | P1 | 4h | - |
| Performance testing | P1 | 4h | - |

### Deliverables
- [ ] Production deployment on datacenter
- [ ] Payment processing working
- [ ] API documentation live
- [ ] Monitoring dashboards
- [ ] Security hardening complete

---

## Post-MVP Roadmap (Phase 7+)

### Month 2: Enhanced Features

| Feature | Description |
|---------|-------------|
| Blocklist Generator | Export in RPZ, BIND, Pi-hole formats |
| Hunt Query Builder | Custom search syntax for power users |
| Webhook Notifications | Real-time alerts for new threats |
| STIX/MISP Export | Standard threat intel formats |

### Month 3: Advanced Intelligence

| Feature | Description |
|---------|-------------|
| Incident Workspace | Case management with IOC expansion |
| Campaign Tracking | Group indicators by campaign |
| DGA Detection | Machine learning for DGA domains |
| African DNS Observatory Integration | Partnership for zone data |

### Month 4: Enterprise Features

| Feature | Description |
|---------|-------------|
| Custom Feed Integration | Bring your own threat feeds |
| White-label Option | Rebrandable for partners |
| On-premise Deployment | Self-hosted option |
| SLA Guarantees | Enterprise support tiers |

---

## Success Metrics

### MVP Launch Criteria

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Indicators ingested | 50K+ | Database count |
| Feed coverage | 5+ sources | Config audit |
| African countries | 45+ | Probe coverage |
| API latency (p95) | < 500ms | APM |
| Uptime | 99% | Monitoring |
| Map render time | < 2s | Lighthouse |

### Post-Launch KPIs

| Metric | Target (3mo) | Target (6mo) |
|--------|--------------|--------------|
| Registered users | 100 | 500 |
| Paid subscribers | 10 | 50 |
| API calls/month | 100K | 500K |
| NOD detection rate | 70% | 85% |
| False positive rate | < 15% | < 10% |

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| RIPE Atlas credit depletion | High | Medium | Monitor credits, implement quotas |
| Vertex AI latency spikes | Medium | Low | Batch scoring, caching |
| Feed API changes | Medium | Medium | Abstraction layer, monitoring |
| Low African probe coverage | Medium | Low | Partner with AfriNIC, incentivize |
| ML model drift | Medium | Medium | Regular retraining, monitoring |

---

## Dependencies

### External Services
- RIPE Atlas (measurement infrastructure)
- Shodan (infrastructure intel)
- Vertex AI (ML inference)
- Mapbox (map tiles)
- Stripe/Paystack (payments)

### Open Source Components
- FastAPI (backend)
- Next.js (frontend)
- PostgreSQL (database)
- ClickHouse (analytics)
- Redis (cache)
- Celery (task queue)
- DNSTwist (typosquatting)

---

## Team Requirements

### Minimum Viable Team
- 1 Full-stack Developer (Python + React)
- 1 DevOps/Infrastructure Engineer (part-time)

### Ideal Team
- 1 Backend Developer (Python/FastAPI)
- 1 Frontend Developer (React/TypeScript)
- 1 Data Engineer (ML pipeline)
- 1 DevOps Engineer (part-time)
- 1 Security Analyst (domain expertise)
