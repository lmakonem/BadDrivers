# JichoDNS API Reference

## Overview

The JichoDNS API provides programmatic access to DNS threat intelligence data focused on African networks. The API follows REST conventions and returns JSON responses.

**Base URL**: `https://api.jichodns.io/v1`

## Authentication

### JWT Authentication (Dashboard Users)

Used for web dashboard access. Obtain a token via login:

```bash
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "your_password"
}
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Use the token in subsequent requests:
```bash
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### API Key Authentication (Paid Tiers)

For programmatic access, use API keys:

```bash
Authorization: Bearer jdns_live_xxxxxxxxxxxxxxxxxxxx
```

API keys are managed in the dashboard under Settings > API Keys.

## Rate Limits

| Tier | Requests/Minute | Requests/Day | Requests/Month |
|------|-----------------|--------------|----------------|
| Free (Registered) | 10 | 100 | 3,000 |
| Professional | 60 | 10,000 | 300,000 |
| Enterprise | 300 | Unlimited | Unlimited |

Rate limit headers are included in all responses:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1710590400
```

## Error Handling

All errors return a consistent format:

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "You have exceeded your rate limit. Try again in 45 seconds.",
    "details": {
      "retry_after": 45
    }
  }
}
```

### Error Codes

| HTTP Status | Code | Description |
|-------------|------|-------------|
| 400 | `invalid_request` | Malformed request |
| 401 | `unauthorized` | Invalid or missing authentication |
| 403 | `forbidden` | Insufficient permissions |
| 404 | `not_found` | Resource not found |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 500 | `internal_error` | Server error |

---

## Public Endpoints

No authentication required.

### Health Check

```
GET /health
```

Response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-03-16T12:00:00Z"
}
```

### Platform Statistics

```
GET /stats
```

Response:
```json
{
  "indicators": {
    "total": 125000,
    "active": 45000,
    "by_type": {
      "c2": 12000,
      "phishing": 28000,
      "exfil": 3000,
      "unknown": 2000
    }
  },
  "coverage": {
    "countries": 48,
    "asns": 234,
    "probes": 156
  },
  "last_updated": "2026-03-16T11:55:00Z"
}
```

### Map Data (Cached)

```
GET /map/regions?threat_type=c2
```

Parameters:
- `threat_type`: `c2`, `phishing`, `exfil`, or `all` (default: `all`)

Response:
```json
{
  "type": "FeatureCollection",
  "features": [
    {
      "type": "Feature",
      "properties": {
        "country_code": "KE",
        "country_name": "Kenya",
        "risk_score": 0.72,
        "indicator_count": 234,
        "threat_breakdown": {
          "c2": 0.45,
          "phishing": 0.65,
          "exfil": 0.12
        }
      },
      "geometry": { "type": "Polygon", "coordinates": [...] }
    }
  ]
}
```

---

## User Endpoints

Requires JWT authentication (registered users).

### Search Indicators

```
GET /indicators
```

Parameters:
- `q`: Search query (domain, IP, or keyword)
- `type`: Filter by type (`c2`, `phishing`, `exfil`)
- `min_risk`: Minimum risk score (0-1)
- `country`: Filter by affected country (ISO code)
- `first_seen_after`: ISO datetime
- `limit`: Results per page (default: 50, max: 100)
- `offset`: Pagination offset

Response:
```json
{
  "total": 1234,
  "limit": 50,
  "offset": 0,
  "results": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "value": "malicious-domain.xyz",
      "type": "c2",
      "risk_score": 0.89,
      "first_seen": "2026-03-16T08:00:00Z",
      "last_seen": "2026-03-16T11:30:00Z",
      "source": "threatfox",
      "malware_family": "emotet",
      "african_exposure": {
        "countries": ["KE", "ZA", "NG"],
        "query_count": 156
      }
    }
  ]
}
```

### Enrich Indicator

```
GET /enrich/domain/{domain}
```

Response:
```json
{
  "domain": "malicious-domain.xyz",
  "classification": {
    "type": "c2",
    "confidence": 0.91,
    "model_version": "v1.2.0"
  },
  "risk_score": 0.89,
  "first_seen": "2026-03-16T08:00:00Z",
  "domain_age_hours": 14,
  "threat_feeds": [
    {
      "source": "threatfox",
      "category": "emotet-c2",
      "added": "2026-03-16T09:00:00Z"
    },
    {
      "source": "virustotal",
      "detections": 12,
      "total_engines": 70
    }
  ],
  "whois": {
    "registrar": "NameCheap",
    "created": "2026-03-15T18:00:00Z",
    "expires": "2027-03-15T18:00:00Z",
    "registrant_country": "PA"
  },
  "infrastructure": {
    "current_ips": ["185.234.x.x"],
    "hosting_asn": "AS12345",
    "hosting_country": "RU",
    "ip_count_24h": 4,
    "ssl_cert": {
      "issuer": "Let's Encrypt",
      "valid_from": "2026-03-15",
      "valid_to": "2026-06-13"
    }
  },
  "dns_behavior": {
    "avg_ttl": 60,
    "record_types": ["A"],
    "resolution_rate": 0.95
  },
  "african_exposure": {
    "total_queries": 234,
    "by_country": {
      "KE": 156,
      "ZA": 45,
      "NG": 33
    },
    "by_asn": [
      {"asn": 33771, "name": "Safaricom", "queries": 89}
    ]
  },
  "typosquat_target": null,
  "related_indicators": [
    {
      "value": "related-domain.xyz",
      "relationship": "shared_ip",
      "risk_score": 0.85
    }
  ]
}
```

### Get Hotspots

```
GET /hotspots
```

Parameters:
- `type`: `country` or `asn` (default: `country`)
- `threat_type`: `c2`, `phishing`, `exfil`, `all`
- `limit`: Number of results (default: 10)
- `period`: `1h`, `24h`, `7d`, `30d` (default: `24h`)

Response:
```json
{
  "period": "24h",
  "type": "country",
  "hotspots": [
    {
      "rank": 1,
      "region_id": "KE",
      "region_name": "Kenya",
      "risk_score": 0.78,
      "indicator_count": 234,
      "trend": "+15%",
      "top_threats": [
        {"type": "phishing", "count": 156},
        {"type": "c2", "count": 78}
      ]
    }
  ]
}
```

### Manage Watchlist

```
GET /watchlist
POST /watchlist
DELETE /watchlist/{id}
```

POST body:
```json
{
  "value": "suspicious-domain.com",
  "type": "domain",
  "notes": "Monitoring for client"
}
```

---

## Paid API Endpoints

Requires API Key authentication (Professional/Enterprise tiers).

### Advanced Search (Hunt Queries)

```
POST /hunt/query
```

Body:
```json
{
  "query": "entropy:>4.0 AND country:KE AND first_seen:>now-24h",
  "limit": 100
}
```

Query syntax:
- `entropy:>4.0` - Domain entropy filter
- `country:KE` - Affected country
- `asn:33771` - Specific ASN
- `type:c2` - Threat type
- `first_seen:>now-24h` - Time filter
- `risk:>0.8` - Risk score filter
- `feed:threatfox` - Source filter

Response:
```json
{
  "query": "entropy:>4.0 AND country:KE AND first_seen:>now-24h",
  "total": 45,
  "results": [...]
}
```

### Export Data

#### STIX 2.1 Export

```
GET /export/stix
```

Parameters:
- `type`: Threat type filter
- `min_risk`: Minimum risk score
- `from`: Start datetime
- `to`: End datetime
- `limit`: Max indicators (default: 1000)

Response: STIX 2.1 Bundle (JSON)

#### MISP Export

```
GET /export/misp
```

Parameters: Same as STIX export

Response: MISP Event format (JSON)

#### Blocklist Export

```
GET /export/blocklist
```

Parameters:
- `format`: `rpz`, `bind`, `hosts`, `pihole`, `unbound`
- `type`: Threat type filter
- `min_confidence`: Minimum confidence (0-100)

Response: Plain text blocklist

### Bulk Lookup

```
POST /bulk/lookup
```

Body:
```json
{
  "indicators": [
    "domain1.com",
    "domain2.xyz",
    "192.168.1.1"
  ]
}
```

Response:
```json
{
  "results": [
    {
      "value": "domain1.com",
      "found": true,
      "risk_score": 0.85,
      "type": "phishing"
    },
    {
      "value": "domain2.xyz",
      "found": false
    }
  ]
}
```

### Webhooks

#### Create Webhook

```
POST /webhooks
```

Body:
```json
{
  "url": "https://your-siem.com/webhook",
  "events": ["new_c2", "new_phishing", "high_risk_nod"],
  "secret": "your_webhook_secret",
  "filters": {
    "countries": ["KE", "ZA"],
    "min_risk": 0.7
  }
}
```

#### Webhook Events

| Event | Description |
|-------|-------------|
| `new_c2` | New C2 indicator detected |
| `new_phishing` | New phishing indicator detected |
| `new_exfil` | New exfiltration indicator detected |
| `high_risk_nod` | High-risk newly observed domain |
| `campaign_detected` | New campaign identified |
| `typosquat_detected` | Typosquatting domain found |

#### Webhook Payload

```json
{
  "event": "new_c2",
  "timestamp": "2026-03-16T12:00:00Z",
  "data": {
    "indicator": {
      "value": "malicious.xyz",
      "type": "c2",
      "risk_score": 0.92
    },
    "african_exposure": {
      "countries": ["KE", "ZA"]
    }
  },
  "signature": "sha256=..."
}
```

---

## Enterprise Endpoints

Requires Enterprise API Key.

### Raw Atlas Events

```
GET /raw/atlas-events
```

Parameters:
- `indicator`: Filter by indicator
- `country`: Filter by probe country
- `from`: Start datetime
- `to`: End datetime
- `limit`: Max events (default: 10000)

### Bulk Export

```
GET /bulk/indicators
```

Parameters:
- `format`: `json`, `csv`, `jsonl`
- `from`: Start datetime
- `compress`: `gzip` (optional)

Returns streaming response for large exports.

### Custom Feed Management

```
POST /feeds/custom
```

Body:
```json
{
  "name": "Internal Threat Feed",
  "url": "https://internal.example.com/feed.json",
  "format": "json",
  "auth": {
    "type": "bearer",
    "token": "..."
  },
  "schedule": "*/15 * * * *"
}
```

---

## SDKs

### Python

```bash
pip install jichodns
```

```python
from jichodns import JichoDNS

client = JichoDNS(api_key="jdns_live_xxx")

# Enrich a domain
result = client.enrich("suspicious-domain.com")
print(result.risk_score)
print(result.classification)

# Search indicators
indicators = client.search(
    type="c2",
    country="KE",
    min_risk=0.7
)

# Export blocklist
blocklist = client.export_blocklist(
    format="rpz",
    min_confidence=80
)
```

### JavaScript/TypeScript

```bash
npm install @jichodns/client
```

```typescript
import { JichoDNS } from '@jichodns/client';

const client = new JichoDNS({ apiKey: 'jdns_live_xxx' });

// Enrich a domain
const result = await client.enrich('suspicious-domain.com');
console.log(result.riskScore);

// Search indicators
const indicators = await client.search({
  type: 'c2',
  country: 'KE',
  minRisk: 0.7
});
```

---

## Changelog

### v1.0.0 (2026-03-16)
- Initial release
- Core endpoints for indicators, enrichment, export
- Webhook support
- STIX/MISP export
