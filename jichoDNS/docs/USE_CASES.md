# JichoDNS Use Cases & Feature Mapping

## Overview

This document maps specific user questions and workflows to JichoDNS features, ensuring the platform addresses real operational needs for SOC analysts, threat hunters, and incident responders in African organizations.

---

## User Persona Questions → Feature Mapping

### SOC Analyst Questions

| Question | Feature | API Endpoint | UI Component |
|----------|---------|--------------|--------------|
| "Is this domain malicious?" | Indicator Enrichment | `GET /enrich/domain/{domain}` | Indicator Detail View |
| "What's the risk score?" | ML Classification | Included in enrichment | Risk Score Badge |
| "When was it first seen?" | First-Seen Tracking | `first_seen` field | Timeline View |
| "What threat feeds flag this?" | Multi-Source Lookup | `threat_feeds` array | Source Badges |
| "Is this typosquatting our brand?" | DNSTwist Integration | `typosquat_target` field | Alert Panel |
| "What countries are affected?" | African Exposure | `african_exposure` object | Map Highlight |
| "Generate a blocklist for me" | Blocklist Export | `GET /export/blocklist` | Export Dialog |

### Threat Hunter Questions

| Question | Feature | API Endpoint | UI Component |
|----------|---------|--------------|--------------|
| "Show me domains < 20 hours old" | NOD Dashboard | `GET /domains/new?max_age_hours=20` | NOD Panel |
| "Find high-entropy domains" | Hunt Query | `POST /hunt/query` with `entropy:>4.0` | Hunt Builder |
| "What DGA patterns are active?" | Pattern Clustering | `GET /patterns/clusters?type=dga` | Patterns Tab |
| "Show me TXT query anomalies" | Query Pattern Analysis | `GET /domains/{d}/patterns` | Pattern Chart |
| "What's deviating from baseline?" | Anomaly Detection | `GET /anomalies` | Anomaly Panel |
| "Find beaconing behavior" | Timing Analysis | `query_interval_stddev` filter | Timeline View |
| "Which ASNs are most affected?" | Hotspots by ASN | `GET /hotspots?type=asn` | Hotspots Panel |

### Incident Responder Questions

| Question | Feature | API Endpoint | UI Component |
|----------|---------|--------------|--------------|
| "What's related to this IOC?" | IOC Expansion | `GET /indicator/{id}/related` | Related Panel |
| "Build me a timeline" | Event Timeline | `GET /indicator/{id}/timeline` | Timeline View |
| "What infrastructure is shared?" | Infrastructure Correlation | `related_by_infrastructure` | Graph View |
| "Export IOCs for my SIEM" | STIX/MISP Export | `GET /export/stix` | Export Dialog |
| "How many of our IPs queried this?" | Exposure Assessment | `african_exposure.by_asn` | Exposure Table |
| "When did the campaign start?" | Campaign Timeline | `GET /campaigns/{id}/timeline` | Campaign View |

### National CERT Questions

| Question | Feature | API Endpoint | UI Component |
|----------|---------|--------------|--------------|
| "What's the threat landscape today?" | Dashboard Overview | `GET /stats/summary` | Main Dashboard |
| "Which sectors are most targeted?" | Sector Analysis | `GET /regions/sectors` | Sector Chart |
| "Show me week-over-week trends" | Trend Analysis | `GET /stats/trends` | Trend Chart |
| "What campaigns target our country?" | Campaign Tracking | `GET /campaigns?country=KE` | Campaign List |
| "Generate a threat brief" | Report Generation | `GET /reports/brief` | Report Builder |

---

## Detailed Feature Specifications

### 1. Indicator Enrichment (SOC Priority)

**Purpose:** Answer "Tell me everything about this indicator"

**API Response Structure:**
```json
{
  "indicator": {
    "value": "suspicious-domain.xyz",
    "type": "domain",
    "classification": {
      "type": "c2",
      "confidence": 0.91,
      "signals": ["high_entropy", "fast_flux", "new_domain"]
    },
    "risk_score": 0.89
  },
  
  "first_seen": {
    "dns": "2026-03-16T08:00:00Z",
    "feed": "2026-03-16T09:00:00Z",
    "age_hours": 14
  },
  
  "threat_intel": {
    "sources": [
      {"name": "ThreatFox", "category": "emotet-c2", "confidence": 90},
      {"name": "VirusTotal", "detections": 12, "total": 70},
      {"name": "AbuseIPDB", "abuse_score": 85}
    ],
    "malware_family": "emotet",
    "campaign": null,
    "tags": ["banking-trojan", "c2"]
  },
  
  "whois": {
    "registrar": "NameCheap",
    "created": "2026-03-15T18:00:00Z",
    "registrant_country": "PA",
    "name_servers": ["ns1.bulletproof.ru"]
  },
  
  "infrastructure": {
    "current_ips": ["185.234.x.x", "91.215.x.x"],
    "ip_count_24h": 4,
    "hosting_asns": [{"asn": 12345, "name": "Bulletproof Host", "country": "RU"}],
    "ssl_cert": {
      "issuer": "Let's Encrypt",
      "subject": "suspicious-domain.xyz",
      "valid_from": "2026-03-15"
    }
  },
  
  "dns_behavior": {
    "resolution_rate": 0.95,
    "avg_rtt_ms": 45,
    "avg_ttl": 60,
    "record_types": ["A"],
    "nxdomain_rate": 0.02
  },
  
  "query_patterns": {
    "txt_ratio": 0.02,
    "unique_subdomains": 5,
    "avg_subdomain_length": 12,
    "subdomain_entropy": 2.1,
    "anomalies": []
  },
  
  "african_exposure": {
    "total_queries": 234,
    "countries": ["KE", "ZA", "NG"],
    "by_country": {"KE": 156, "ZA": 45, "NG": 33},
    "by_asn": [
      {"asn": 33771, "name": "Safaricom", "queries": 89},
      {"asn": 37100, "name": "MTN SA", "queries": 45}
    ],
    "first_query": "2026-03-16T08:30:00Z"
  },
  
  "typosquatting": {
    "is_typosquat": false,
    "target": null,
    "similarity": null,
    "fuzzer_type": null
  },
  
  "related_indicators": [
    {"value": "related-domain.xyz", "relationship": "shared_ip", "confidence": 0.85},
    {"value": "another-c2.xyz", "relationship": "same_campaign", "confidence": 0.72}
  ]
}
```

**UI Components:**
- Risk score badge with color coding
- Threat source pills
- Infrastructure timeline graph
- African exposure map highlight
- Related indicators panel

---

### 2. Newly Observed Domains Dashboard (Hunter Priority)

**Purpose:** "Show me domains that appeared in the last 20 hours"

**API Endpoint:** `GET /domains/new`

**Parameters:**
```
max_age_hours: 20          # Maximum domain age
min_risk: 0.5              # Minimum risk score
threat_type: c2,phishing   # Filter by type
country: KE                # Filter by affected country
sort: risk_score           # Sort order
limit: 100                 # Results per page
```

**Response:**
```json
{
  "total": 127,
  "filters_applied": {
    "max_age_hours": 20,
    "min_risk": 0.5
  },
  "summary": {
    "high_risk": 23,
    "medium_risk": 67,
    "low_risk": 37,
    "by_type": {"c2": 34, "phishing": 56, "exfil": 8, "unknown": 29}
  },
  "results": [
    {
      "domain": "xyzbank-login.co.za",
      "age_hours": 2,
      "risk_score": 0.94,
      "classification": "phishing",
      "signals": ["typosquat", "new_registration", "suspicious_tld"],
      "typosquat_target": "absa.co.za",
      "african_exposure": {"countries": ["ZA"], "query_count": 12}
    }
  ]
}
```

**UI Components:**
- Age distribution chart
- Risk breakdown pie chart
- Filterable/sortable table
- Quick actions (add to watchlist, export)

---

### 3. Query Pattern Analysis (Hunter/IR Priority)

**Purpose:** "What is this domain sending? Show me the DNS behavior patterns"

**API Endpoint:** `GET /domains/{domain}/patterns`

**Response:**
```json
{
  "domain": "suspicious-update.safaricom-api.xyz",
  "period": "24h",
  
  "query_distribution": {
    "total": 456,
    "by_type": {"A": 98, "AAAA": 12, "TXT": 340, "MX": 6},
    "by_hour": [/* 24 data points */]
  },
  
  "txt_analysis": {
    "ratio": 0.75,
    "baseline_ratio": 0.03,
    "anomaly_score": 0.98,
    "is_anomalous": true
  },
  
  "subdomain_analysis": {
    "unique_count": 234,
    "avg_length": 42,
    "max_length": 63,
    "avg_entropy": 4.2,
    "encoding_detected": "base64",
    "samples": [
      {
        "subdomain": "aGVsbG8gd29ybGQgdGhpcyBpcyBh",
        "decoded": "hello world this is a",
        "length": 28,
        "entropy": 4.1
      }
    ]
  },
  
  "response_patterns": {
    "success_rate": 0.66,
    "nxdomain_rate": 0.34,
    "avg_ttl": 60,
    "ttl_variance": 5,
    "unique_answer_ips": 5
  },
  
  "timing_analysis": {
    "query_intervals": {
      "mean": 312,
      "stddev": 45,
      "is_periodic": true
    },
    "beaconing_score": 0.85
  },
  
  "geographic_distribution": {
    "countries": ["KE", "ZA", "NG"],
    "by_asn": [
      {"asn": 33771, "name": "Safaricom", "queries": 156, "unique_resolvers": 23}
    ]
  },
  
  "verdict": {
    "pattern_type": "dns_exfiltration",
    "confidence": 0.92,
    "evidence": [
      "TXT query ratio 25x above baseline",
      "Subdomain entropy indicates encoded data",
      "Base64 encoding detected in subdomains",
      "Regular 5-minute query intervals (beaconing)"
    ]
  }
}
```

**UI Components:**
- Query type pie chart
- Subdomain length histogram
- Entropy distribution chart
- Decoded subdomain samples
- Timeline with query intervals

---

### 4. Typosquatting Detection (SOC Priority)

**Purpose:** "Are there domains impersonating our brands?"

**API Endpoint:** `GET /typosquat/monitor`

**Response:**
```json
{
  "monitored_brands": 15,
  "active_detections": 47,
  "last_scan": "2026-03-16T12:00:00Z",
  
  "by_brand": [
    {
      "brand": "Safaricom",
      "legitimate_domains": ["safaricom.co.ke", "safaricom.com"],
      "detections": [
        {
          "domain": "safarlcom.co.ke",
          "fuzzer_type": "homoglyph",
          "similarity_score": 0.95,
          "registered": true,
          "resolves_to": ["185.234.x.x"],
          "hosting_country": "RU",
          "has_web": true,
          "has_mx": true,
          "ssl_issuer": "Let's Encrypt",
          "risk_score": 0.92,
          "first_detected": "2026-03-15T14:00:00Z"
        },
        {
          "domain": "safaricom-login.xyz",
          "fuzzer_type": "addition",
          "similarity_score": 0.88,
          "registered": true,
          "resolves_to": ["91.215.x.x"],
          "risk_score": 0.89
        }
      ]
    },
    {
      "brand": "M-Pesa",
      "legitimate_domains": ["safaricom.co.ke/mpesa"],
      "detections": [
        {
          "domain": "mpesa-verify.com",
          "fuzzer_type": "addition",
          "similarity_score": 0.82,
          "registered": true,
          "risk_score": 0.87
        }
      ]
    }
  ],
  
  "recent_registrations": [
    {
      "domain": "safarlcom-update.com",
      "registered_at": "2026-03-16T08:00:00Z",
      "target_brand": "Safaricom",
      "risk_score": 0.91
    }
  ]
}
```

**UI Components:**
- Brand monitoring dashboard
- Visual domain comparison
- Registration timeline
- Risk matrix by brand

---

### 5. Hotspots & Regional Analysis (CERT Priority)

**Purpose:** "Which countries/ASNs have the most threats?"

**API Endpoint:** `GET /hotspots`

**Parameters:**
```
type: country|asn          # Region type
threat_type: c2,phishing   # Threat filter
period: 24h|7d|30d         # Time period
limit: 20                  # Results
```

**Response:**
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
      "query_count": 45678,
      "trend": "+15%",
      "trend_direction": "up",
      "threat_breakdown": {
        "c2": {"count": 89, "risk": 0.82},
        "phishing": {"count": 123, "risk": 0.75},
        "exfil": {"count": 22, "risk": 0.65}
      },
      "top_indicators": [
        {"value": "malicious.xyz", "type": "c2", "queries": 156}
      ],
      "affected_asns": [
        {"asn": 33771, "name": "Safaricom", "indicator_count": 45}
      ]
    }
  ],
  
  "comparison": {
    "vs_yesterday": {
      "total_indicators": "+12%",
      "new_domains": "+23%",
      "c2_activity": "-5%"
    }
  }
}
```

**UI Components:**
- Country ranking table
- Risk trend sparklines
- Threat type breakdown bars
- Week-over-week comparison

---

### 6. Campaign Tracking (Hunter/IR Priority)

**Purpose:** "What campaigns are active? Group related indicators"

**API Endpoint:** `GET /campaigns`

**Response:**
```json
{
  "active_campaigns": 12,
  
  "campaigns": [
    {
      "id": "campaign-safari-phish-2026",
      "name": "Safari Phish",
      "status": "active",
      "first_seen": "2026-03-10T00:00:00Z",
      "last_activity": "2026-03-16T12:00:00Z",
      
      "classification": {
        "type": "phishing",
        "targets": ["M-Pesa", "Safaricom", "Airtel Money"],
        "ttps": ["typosquatting", "sms_phishing", "credential_harvesting"]
      },
      
      "indicators": {
        "total": 89,
        "domains": 67,
        "ips": 12,
        "urls": 10
      },
      
      "infrastructure": {
        "registrars": ["NameCheap"],
        "hosting_countries": ["RU", "UA"],
        "hosting_asns": [12345, 67890],
        "ssl_issuers": ["Let's Encrypt"]
      },
      
      "geographic_impact": {
        "countries": ["KE", "TZ", "UG"],
        "primary_target": "KE",
        "estimated_victims": 1200
      },
      
      "timeline": [
        {"date": "2026-03-10", "event": "First domain registered"},
        {"date": "2026-03-12", "event": "Campaign went active"},
        {"date": "2026-03-14", "event": "Added to ThreatFox"},
        {"date": "2026-03-15", "event": "New domains added"}
      ],
      
      "attribution": {
        "actor": null,
        "confidence": "low",
        "similar_campaigns": ["mpesa-phish-2025"]
      }
    }
  ]
}
```

**UI Components:**
- Campaign cards with status
- Target brand logos
- Infrastructure graph
- Activity timeline
- IOC expansion panel

---

### 7. Baseline Deviation & Anomaly Detection (Hunter Priority)

**Purpose:** "What's abnormal compared to baseline?"

**API Endpoint:** `GET /anomalies`

**Response:**
```json
{
  "period": "24h",
  "region": "KE",
  
  "baseline_deviations": [
    {
      "metric": "new_domains_per_hour",
      "baseline": 45,
      "current": 127,
      "deviation_percent": 182,
      "severity": "high",
      "description": "New domain registrations 2.8x above normal"
    },
    {
      "metric": "txt_query_ratio",
      "baseline": 0.03,
      "current": 0.11,
      "deviation_percent": 267,
      "severity": "critical",
      "description": "TXT queries significantly elevated - possible exfiltration"
    },
    {
      "metric": "nxdomain_rate",
      "baseline": 0.08,
      "current": 0.12,
      "deviation_percent": 50,
      "severity": "medium",
      "description": "NXDOMAIN rate elevated - possible DGA activity"
    }
  ],
  
  "detected_anomalies": [
    {
      "type": "dga_cluster",
      "severity": "high",
      "description": "89 domains matching DGA pattern detected",
      "indicators": ["abc123.xyz", "def456.xyz"],
      "likely_family": "Emotet variant"
    },
    {
      "type": "infrastructure_cluster",
      "severity": "medium",
      "description": "34 new domains on 3 suspicious IPs",
      "ips": ["185.234.x.x"],
      "not_in_feeds": true
    }
  ]
}
```

**UI Components:**
- Deviation meter gauges
- Anomaly alert cards
- Historical comparison chart
- Drill-down to affected indicators

---

### 8. IOC Expansion & Correlation (IR Priority)

**Purpose:** "Given this IOC, find everything related"

**API Endpoint:** `GET /indicator/{id}/related`

**Response:**
```json
{
  "seed_indicator": {
    "id": "uuid",
    "value": "malicious-c2.xyz",
    "type": "c2"
  },
  
  "expansion": {
    "by_infrastructure": {
      "count": 12,
      "indicators": [
        {
          "value": "related-domain.xyz",
          "relationship": "shared_ip",
          "shared_resource": "185.234.x.x",
          "confidence": 0.95
        }
      ]
    },
    
    "by_pattern": {
      "count": 8,
      "indicators": [
        {
          "value": "similar-pattern.xyz",
          "relationship": "similar_registration_pattern",
          "confidence": 0.78
        }
      ]
    },
    
    "by_campaign": {
      "count": 34,
      "campaign": "emotet-march-2026",
      "indicators": [/* ... */]
    },
    
    "by_certificate": {
      "count": 5,
      "indicators": [
        {
          "value": "cert-related.xyz",
          "relationship": "shared_certificate",
          "cert_fingerprint": "sha256:...",
          "confidence": 0.92
        }
      ]
    },
    
    "by_temporal": {
      "count": 5,
      "indicators": [
        {
          "value": "same-time.xyz",
          "relationship": "registered_same_day",
          "confidence": 0.65
        }
      ]
    }
  },
  
  "total_related": 47,
  
  "graph": {
    "nodes": [/* indicator nodes */],
    "edges": [/* relationship edges */]
  }
}
```

**UI Components:**
- Relationship graph visualization
- Expansion controls (depth, type)
- Bulk add to incident
- Export all related IOCs

---

### 9. Export & Integration (All Personas)

**Purpose:** "Give me data in a format I can use"

**Export Formats:**

| Format | Endpoint | Use Case |
|--------|----------|----------|
| STIX 2.1 | `GET /export/stix` | SIEM integration, threat sharing |
| MISP Event | `GET /export/misp` | MISP import, community sharing |
| CSV | `GET /export/csv` | Spreadsheet analysis |
| DNS RPZ | `GET /export/blocklist?format=rpz` | BIND DNS firewall |
| Pi-hole | `GET /export/blocklist?format=pihole` | Pi-hole blocklist |
| Hosts file | `GET /export/blocklist?format=hosts` | Local blocking |
| Snort/Suricata | `GET /export/ids` | IDS rules (future) |

**STIX 2.1 Bundle Example:**
```json
{
  "type": "bundle",
  "id": "bundle--uuid",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--uuid",
      "pattern": "[domain-name:value = 'malicious.xyz']",
      "pattern_type": "stix",
      "valid_from": "2026-03-16T00:00:00Z",
      "labels": ["malicious-activity", "c2"],
      "confidence": 90
    },
    {
      "type": "malware",
      "id": "malware--uuid",
      "name": "Emotet",
      "malware_types": ["bot", "trojan"]
    },
    {
      "type": "relationship",
      "relationship_type": "indicates",
      "source_ref": "indicator--uuid",
      "target_ref": "malware--uuid"
    }
  ]
}
```

---

## UI Layout Specification

### Main Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ HEADER                                                                       │
│ ┌─────────────────┬──────────────────┬─────────────────┬──────────────────┐ │
│ │ Logo            │ Time: [24h ▼]    │ Type: [All ▼]   │ Search [______] │ │
│ └─────────────────┴──────────────────┴─────────────────┴──────────────────┘ │
├───────────────┬─────────────────────────────────────────┬───────────────────┤
│ LEFT PANEL    │ CENTER: MAP                             │ RIGHT PANEL       │
│               │                                         │                   │
│ FILTERS       │ ┌─────────────────────────────────────┐ │ TABS              │
│ ┌───────────┐ │ │                                     │ │ [Hotspots]        │
│ │ Region    │ │ │        AFRICA MAP                   │ │ [NOD <20h]        │
│ │ [Africa▼] │ │ │        (Choropleth)                 │ │ [Indicators]      │
│ ├───────────┤ │ │                                     │ │ [Campaigns]       │
│ │ Countries │ │ │     Risk colors by country/ASN     │ │                   │
│ │ □ Kenya   │ │ │                                     │ │ ┌───────────────┐ │
│ │ □ S.Africa│ │ │     Hover: Quick stats             │ │ │ KE  0.78 ▲15% │ │
│ │ □ Nigeria │ │ │     Click: Open detail panel       │ │ │ ZA  0.65 ▼5%  │ │
│ ├───────────┤ │ │                                     │ │ │ NG  0.62 ▲8%  │ │
│ │ ASNs      │ │ │                                     │ │ │ EG  0.58 ─    │ │
│ │ [Select▼] │ │ │                                     │ │ │ GH  0.52 ▲12% │ │
│ ├───────────┤ │ └─────────────────────────────────────┘ │ └───────────────┘ │
│ │ Threat    │ │                                         │                   │
│ │ ● C2      │ │ LEGEND                                  │ [View All →]      │
│ │ ● Phishing│ │ Low ████████████████ High              │                   │
│ │ ● Exfil   │ │                                         │                   │
│ └───────────┘ │                                         │                   │
├───────────────┴─────────────────────────────────────────┴───────────────────┤
│ BOTTOM: INDICATOR TABLE                                                      │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ Domain          │ Type    │ Risk  │ Age   │ Feeds  │ Countries │ Actions│ │
│ ├─────────────────┼─────────┼───────┼───────┼────────┼───────────┼────────┤ │
│ │ malicious.xyz   │ 🔴 C2   │ 0.92  │ 4h    │ 3      │ KE,ZA     │ ⋮      │ │
│ │ phish-bank.com  │ 🟡 Phish│ 0.85  │ 12h   │ 2      │ NG        │ ⋮      │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Indicator Detail Modal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ INDICATOR DETAIL: malicious-c2.xyz                              [X] Close  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ VERDICT: 🔴 HIGH RISK - C2 Infrastructure         Risk Score: 0.92     │ │
│ │ Classification: Command & Control (91% confidence)                      │ │
│ │ First Seen: 4 hours ago │ Domain Age: 1 day │ Active: Yes               │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ TABS: [Overview] [Patterns] [Infrastructure] [Timeline] [Related]          │
│                                                                             │
│ ┌─────────────────────────────┬───────────────────────────────────────────┐ │
│ │ THREAT INTELLIGENCE         │ AFRICAN EXPOSURE                          │ │
│ │                             │                                           │ │
│ │ Sources:                    │ Total Queries: 234                        │ │
│ │ ✓ ThreatFox (Emotet C2)    │                                           │ │
│ │ ✓ VirusTotal (12/70)       │ ┌─────────────────────────────────────┐   │ │
│ │ ✓ AbuseIPDB (Score: 85)    │ │ [MAP: Africa with KE,ZA,NG highlighted]│ │
│ │ ○ PhishTank (Not listed)   │ └─────────────────────────────────────┘   │ │
│ │                             │                                           │ │
│ │ Malware Family: Emotet     │ By Country:                               │ │
│ │ Campaign: emotet-mar-2026  │ KE: 156 (67%)  ZA: 45 (19%)  NG: 33 (14%)│ │
│ │ Tags: banking-trojan, c2   │                                           │ │
│ ├─────────────────────────────┼───────────────────────────────────────────┤ │
│ │ WHOIS                       │ INFRASTRUCTURE                            │ │
│ │                             │                                           │ │
│ │ Registrar: NameCheap       │ Current IPs:                              │ │
│ │ Created: 2026-03-15        │ • 185.234.x.x (AS12345, RU)              │ │
│ │ Expires: 2027-03-15        │ • 91.215.x.x (AS67890, UA)               │ │
│ │ Registrant: REDACTED       │                                           │ │
│ │ Name Servers:              │ IP Rotation: 4 IPs in 24h (Fast-flux)    │ │
│ │ • ns1.bulletproof.ru       │ TTL: 60 seconds (Low)                    │ │
│ │                             │ SSL: Let's Encrypt (Auto-generated)      │ │
│ └─────────────────────────────┴───────────────────────────────────────────┘ │
│                                                                             │
│ ACTIONS:                                                                    │
│ [Add to Watchlist] [Export IOCs] [Find Related] [Generate Blocklist]       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Database Requirements Summary

To support all these features, ensure the database schema includes:

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `indicators` | Core IOC storage | value, type, classification, risk_score, first_seen |
| `indicator_scores` | ML scores over time | c2_prob, exfil_prob, phishing_prob, scored_at |
| `domain_observations` | First-seen tracking | first_seen_dns, whois_created_at, domain_age_hours |
| `query_patterns` | DNS behavior | txt_ratio, subdomain_entropy, beaconing_score |
| `typosquat_targets` | Brands to monitor | brand_name, legitimate_domains |
| `typosquat_detections` | Found lookalikes | domain, fuzzer_type, similarity_score |
| `pattern_clusters` | DGA/campaign groups | cluster_type, member_count, malware_family |
| `region_scores` | Country/ASN risk | region_id, c2_risk, phishing_risk, indicator_count |
| `atlas_events` | RIPE Atlas results | probe_id, probe_cc, dns_rtt, dns_answer_ips |
| `campaigns` | Threat campaigns | name, status, indicators, targets |
| `incidents` | IR workspaces | title, status, related_indicators |

---

## API Endpoint Summary

| Category | Endpoints | Auth Level |
|----------|-----------|------------|
| **Health** | `GET /health` | Public |
| **Stats** | `GET /stats/summary` | Public |
| **Map** | `GET /map/regions` | Public |
| **Search** | `GET /indicators` | User |
| **Enrichment** | `GET /enrich/domain/{d}` | User |
| **NOD** | `GET /domains/new` | User |
| **Patterns** | `GET /domains/{d}/patterns` | User |
| **Hotspots** | `GET /hotspots` | User |
| **Typosquat** | `GET /typosquat/monitor` | User |
| **Anomalies** | `GET /anomalies` | User |
| **Related** | `GET /indicator/{id}/related` | User |
| **Campaigns** | `GET /campaigns` | User |
| **Hunt** | `POST /hunt/query` | Paid |
| **Export** | `GET /export/*` | Paid |
| **Webhooks** | `POST /webhooks` | Paid |
| **Bulk** | `GET /bulk/*` | Enterprise |
