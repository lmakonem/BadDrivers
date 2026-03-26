# AGENTS.md - JichoDNS Development Guide

This document provides guidance for AI coding assistants and developers working on the JichoDNS codebase.

## Project Overview

JichoDNS is an Africa-focused DNS threat visibility platform. It provides:

- **Interactive Threat Map**: Choropleth visualization of C2/Exfil/Phishing risk by country and ASN
- **DNS Threat Intelligence**: Aggregation from 15+ free threat feeds
- **RIPE Atlas Integration**: Active DNS measurements from African vantage points
- **ML Classification**: Vertex AI-powered threat detection
- **Typosquatting Detection**: African brand monitoring (M-Pesa, Safaricom, banks)
- **Paid API Access**: REST API for SOC/SIEM integration

## Repository Structure

```
jichoDNS/
├── AGENTS.md                 # This file
├── README.md                 # Project overview and quick start
├── docker-compose.yml        # Local development stack
├── .env.example              # Environment template
├── assets/                   # Static assets (logo)
├── docs/                     # Documentation
│   ├── ARCHITECTURE.md       # System design
│   ├── API.md                # API reference
│   ├── DATA_SOURCES.md       # Threat feed details
│   ├── DATABASE.md           # Schema documentation
│   ├── DEPLOYMENT.md         # Production deployment
│   ├── ROADMAP.md            # Implementation phases
│   ├── MONETIZATION.md       # Pricing tiers
│   ├── USE_CASES.md          # User personas and workflows
│   └── DNS_ANALYSIS.md       # DNS analysis algorithms
├── backend/                  # FastAPI Python backend
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py           # FastAPI app entry point
│       ├── worker.py         # Celery worker config
│       ├── core/             # Core utilities
│       │   ├── config.py     # Settings and env vars
│       │   ├── logging.py    # Logging configuration
│       │   └── security.py   # Auth and API keys
│       ├── api/              # API endpoints
│       │   ├── health.py     # Health check endpoint
│       │   └── v1/endpoints/ # Versioned API endpoints
│       │       ├── indicators.py
│       │       ├── regions.py
│       │       ├── analysis.py
│       │       └── atlas.py
│       ├── services/         # Business logic
│       │   └── dns_analysis.py  # DNS threat analysis
│       ├── models/           # SQLAlchemy models (to be added)
│       └── importers/        # Feed importers (to be added)
└── frontend/                 # Next.js 14 frontend (to be added)
    └── public/images/        # Public images
```

## Tech Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Backend API | FastAPI | Latest |
| Python | Python | 3.11+ |
| Frontend | Next.js | 14 |
| Database | PostgreSQL | 15+ |
| Analytics DB | ClickHouse | Latest |
| Search/IOC Store | Elasticsearch | 8.x |
| Visualization | Kibana | 8.x |
| Task Queue | Celery + Redis | Latest |
| Maps | Mapbox GL JS | Latest |
| ML | Vertex AI | - |

## Development Environment

### Local Development

```bash
# Start local services
docker-compose up -d

# API runs on http://localhost:8000
# Docs at http://localhost:8000/docs
```

### Production Servers

| Server | IP | Services |
|--------|-----|----------|
| App Server (VM 110) | 192.168.36.50 | API, Workers, Frontend |
| DB Server (VM 111) | 192.168.36.51 | PostgreSQL, ClickHouse, Redis, Elasticsearch, Kibana |

## Code Style and Conventions

### Python (Backend)

- **Style**: Follow PEP 8
- **Type Hints**: Use type hints for all functions
- **Async**: Use async/await for I/O-bound operations
- **Docstrings**: Google-style docstrings
- **Tests**: pytest with pytest-asyncio

```python
from typing import Optional

async def analyze_domain(domain: str, deep_scan: bool = False) -> dict:
    """
    Analyze a domain for threat indicators.
    
    Args:
        domain: The domain name to analyze
        deep_scan: Whether to perform deep analysis
        
    Returns:
        Dictionary with analysis results including risk_score and threat_type
    """
    pass
```

### TypeScript (Frontend)

- **Style**: ESLint with Airbnb config
- **Components**: Functional components with hooks
- **State**: TanStack Query for server state
- **Styling**: Tailwind CSS

### API Design

- **Versioning**: `/api/v1/` prefix for all endpoints
- **Response Format**: JSON with consistent structure
- **Error Handling**: Standard HTTP status codes with error details
- **Pagination**: Cursor-based for large datasets

```json
{
  "data": [...],
  "meta": {
    "total": 100,
    "page": 1,
    "per_page": 20
  }
}
```

## Key Components

### DNS Analysis Service

Located in `backend/app/services/dns_analysis.py`:

- **Entropy Calculation**: Shannon entropy for randomness detection
- **N-gram Analysis**: Impossible consonant combinations (qh, xz, etc.)
- **DGA Scoring**: Domain Generation Algorithm detection
- **Risk Classification**: C2, Exfiltration, Phishing, Benign

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/indicators` | GET/POST | IOC management |
| `/api/v1/regions` | GET | Regional threat data |
| `/api/v1/analysis` | POST | Analyze domains |
| `/api/v1/atlas` | GET/POST | RIPE Atlas measurements |

### Feed Importers (To Be Implemented)

Priority feeds for implementation:

1. **Abuse.ch** - URLhaus, ThreatFox, Feodo Tracker
2. **PhishTank** - Phishing URLs
3. **AlienVault OTX** - Multi-source intelligence
4. **Certificate Transparency** - crt.sh

## Database Schemas

### PostgreSQL Tables

- `indicators` - IOCs (domains, IPs, URLs)
- `indicator_scores` - ML-generated risk scores
- `region_scores` - Aggregated country/ASN scores
- `users` - User accounts
- `api_keys` - API key management

### ClickHouse Tables

- `dns_events` - High-volume DNS query logs
- `atlas_measurements` - RIPE Atlas results

### Elasticsearch Indices

- `iocs` - IOC search and correlation
- `dns_queries` - Query analytics

## Testing

```bash
# Run all tests
cd backend && pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_dns_analysis.py -v
```

## Common Tasks

### Adding a New Feed Importer

1. Create file in `backend/app/importers/`
2. Implement base class interface
3. Add Celery task in `worker.py`
4. Configure schedule in Celery beat

### Adding a New API Endpoint

1. Create endpoint in `backend/app/api/v1/endpoints/`
2. Add Pydantic schemas for request/response
3. Register in router
4. Add tests

### Adding ML Classification

1. Define feature extraction in `services/dns_analysis.py`
2. Create Vertex AI model endpoint
3. Implement scoring pipeline
4. Store results in `indicator_scores`

## Environment Variables

Key environment variables (see `.env.example`):

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/jichodns
CLICKHOUSE_URL=clickhouse://user:pass@host:9000/jichodns
REDIS_URL=redis://:pass@host:6379/0
ELASTICSEARCH_URL=http://elastic:pass@host:9200

# External APIs
RIPE_ATLAS_API_KEY=your_key
SHODAN_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key

# Security
SECRET_KEY=your_secret_key
API_KEY_SALT=your_salt
```

## Deployment

### Docker Build

```bash
# Build API image
cd backend && docker build -t jichodns-api .

# Build frontend (when ready)
cd frontend && docker build -t jichodns-frontend .
```

### Production Commands

```bash
# SSH to servers
ssh localuser@192.168.36.50  # App server
ssh localuser@192.168.36.51  # DB server

# Check service status
docker compose ps
docker compose logs -f api
```

## Performance Considerations

- **Caching**: Use Redis for frequently accessed data (region scores, indicator lookups)
- **Batch Processing**: Bulk insert indicators, don't insert one at a time
- **Connection Pooling**: Use connection pools for all databases
- **Async Operations**: All I/O should be async in FastAPI

## Security Notes

- Never commit `.env` files or credentials
- API keys should be hashed with SHA-256 before storage
- All user input must be validated with Pydantic
- Use parameterized queries (SQLAlchemy handles this)
- Rate limit all API endpoints

## Africa-Specific Considerations

This platform focuses on African threat intelligence:

- **Target ASNs**: Major African ISPs and telecoms
- **Brand Monitoring**: M-Pesa, Safaricom, Airtel, MTN, major banks
- **RIPE Atlas Probes**: Prioritize probes in African countries
- **Threat Context**: Mobile money fraud, SMS phishing are prevalent

## Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [RIPE Atlas API](https://atlas.ripe.net/docs/apis/)
- [Abuse.ch API](https://urlhaus.abuse.ch/api/)
- [Elasticsearch Guide](https://www.elastic.co/guide/)
- [ClickHouse Documentation](https://clickhouse.com/docs)
