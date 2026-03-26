<p align="center">
  <img src="assets/logo.png" alt="JichoDNS Logo" width="300">
</p>

<h1 align="center">JichoDNS</h1>

<p align="center">
  <strong>Africa-focused DNS threat visibility platform</strong>
</p>

<p align="center">
  <a href="#key-features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Docs</a> •
  <a href="#api-access-tiers">API</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.11+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/Next.js-14-black.svg" alt="Next.js">
</p>

---

JichoDNS provides real-time DNS threat intelligence for African networks, combining RIPE Atlas measurements, multi-source threat feeds, and ML-powered classification to detect C2 infrastructure, data exfiltration, and phishing campaigns targeting the continent.

> "Jicho" means "eye" in Swahili - JichoDNS is the watchful eye over Africa's DNS landscape.

## Key Features

- **Interactive Africa Threat Map** - Choropleth visualization of C2/Exfil/Phishing risk by country and ASN
- **Newly Observed Domains (NOD)** - Track domains less than 20 hours old with risk scoring
- **Multi-Source Intelligence** - Aggregates 15+ threat feeds (Abuse.ch, PhishTank, OTX, etc.)
- **RIPE Atlas Integration** - Active DNS measurements from African vantage points
- **ML Classification** - Vertex AI-powered C2/Exfil/Phishing detection
- **Typosquatting Detection** - DNSTwist integration for African brand monitoring
- **Infrastructure Correlation** - Shodan integration for hosting intelligence
- **Paid API Access** - REST API for SOC/SIEM integration with STIX/MISP export

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                             │
├──────────────┬──────────────┬──────────────┬───────────────────┤
│  Abuse.ch    │  PhishTank   │  RIPE Atlas  │     Shodan        │
│  ThreatFox   │  OTX         │              │                   │
└──────┬───────┴──────┬───────┴──────┬───────┴───────┬───────────┘
       │              │              │               │
       ▼              ▼              ▼               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CELERY WORKERS                                │
│  Feed Import │ Atlas Scheduler │ Enrichment │ ML Scoring        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
   ┌───────────┐    ┌───────────┐    ┌───────────┐
   │ PostgreSQL│    │ClickHouse │    │   Redis   │
   └─────┬─────┘    └─────┬─────┘    └───────────┘
         └────────┬───────┘
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FASTAPI BACKEND                             │
│  Public API │ User API │ Paid API │ Admin API                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
┌─────────────────────┐          ┌─────────────────────┐
│   Next.js Frontend  │          │  External API       │
│   (Dashboard)       │          │  Consumers          │
└─────────────────────┘          └─────────────────────┘
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- RIPE Atlas API key
- Shodan API key (Membership)
- Google Cloud account (Vertex AI)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/jichoDNS.git
cd jichoDNS

# Copy environment template
cp .env.example .env

# Edit .env with your API keys
nano .env

# Start the stack
docker-compose up -d

# Run database migrations
docker-compose exec backend alembic upgrade head

# Access the dashboard
open http://localhost:3000
```

### Environment Variables

```bash
# Required
RIPE_ATLAS_API_KEY=your_ripe_atlas_key
SHODAN_API_KEY=your_shodan_key
GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json

# Database
POSTGRES_HOST=postgres
POSTGRES_DB=jichodns
POSTGRES_USER=jichodns
POSTGRES_PASSWORD=secure_password

# Optional integrations
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design and component details |
| [API Reference](docs/API.md) | Complete API documentation |
| [Data Sources](docs/DATA_SOURCES.md) | Threat feed integrations |
| [Database Schema](docs/DATABASE.md) | PostgreSQL and ClickHouse schemas |
| [Deployment](docs/DEPLOYMENT.md) | Production deployment guide |
| [Roadmap](docs/ROADMAP.md) | Implementation phases |
| [Monetization](docs/MONETIZATION.md) | Pricing tiers and API access |

## API Access Tiers

| Tier | Price | API Calls | Features |
|------|-------|-----------|----------|
| **Public** | Free | - | View map, basic stats |
| **Registered** | Free | 100/day | Dashboard, lookups, watchlists |
| **Professional** | $49/mo | 10K/mo | Full API, exports, webhooks |
| **Enterprise** | $299/mo | Unlimited | Bulk, custom feeds, support |

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | FastAPI (Python 3.11+) |
| Frontend | Next.js 14, TypeScript, Tailwind CSS |
| Maps | Mapbox GL JS |
| Database | PostgreSQL 15, ClickHouse |
| Queue | Celery, Redis |
| ML | Vertex AI (HuggingFace models) |
| Auth | JWT, API Keys |
| Payments | Stripe, Paystack |

## Use Cases

### SOC Analyst
- Triage alerts with instant indicator enrichment
- Identify Africa-specific threats
- Generate blocklists for DNS firewalls

### Threat Hunter
- Discover newly observed malicious domains
- Track DGA patterns and campaigns
- Correlate infrastructure across indicators

### Incident Responder
- Scope incidents with IOC expansion
- Build attack timelines
- Export evidence in standard formats

### National CERT
- Monitor threat landscape across all national ASNs
- Track campaigns targeting the country
- Share intelligence with stakeholders

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [RIPE NCC](https://atlas.ripe.net/) - Atlas measurement infrastructure
- [abuse.ch](https://abuse.ch/) - Threat intelligence feeds
- [Shodan](https://shodan.io/) - Internet intelligence
- [DNSTwist](https://github.com/elceef/dnstwist) - Domain permutation engine
