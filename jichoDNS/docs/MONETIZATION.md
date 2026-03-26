# JichoDNS Monetization Strategy

## Overview

JichoDNS follows an **open-core model** with a free public dashboard and paid API access for SOC/SIEM integration.

---

## Pricing Tiers

### Free Tier: Public Dashboard

**Price:** $0

**Access:**
- Public web interface (no login required)
- View-only access to threat map
- Limited statistics (top 10 hotspots)
- No API access

**Use Case:** Security researchers, students, casual users

---

### Registered Tier: Free Account

**Price:** $0 (email registration required)

**Access:**
- Full dashboard access
- Indicator search (100 queries/day)
- Indicator enrichment (100 lookups/day)
- Watchlists (5 items max)
- Email alerts (weekly digest)
- No API access

**Use Case:** Individual security professionals, small organizations

**Limits:**
```
Daily lookups: 100
Watchlist items: 5
Alert frequency: Weekly
Export: None
```

---

### Professional Tier

**Price:** $49/month (or $490/year - 2 months free)

**Access:**
- Everything in Registered tier
- **Full REST API access**
- 10,000 API calls/month
- STIX 2.1 export
- MISP event export
- Blocklist generation (RPZ, BIND, Pi-hole)
- Webhook notifications (5 endpoints)
- Watchlists (100 items)
- Real-time alerts
- Email support (48h response)

**Use Case:** SOC teams, threat hunters, security consultants

**API Rate Limits:**
```
Requests per minute: 60
Requests per day: 10,000
Requests per month: 300,000
Concurrent requests: 10
```

---

### Enterprise Tier

**Price:** $299/month (or $2,990/year)

**Access:**
- Everything in Professional tier
- **Unlimited API calls**
- Bulk export endpoints
- Custom feed integration
- Priority webhook delivery
- Dedicated support channel
- SLA guarantee (99.9% uptime)
- Custom integrations
- On-premise deployment option (additional cost)

**Use Case:** Telecoms, banks, CERTs, government agencies

**API Rate Limits:**
```
Requests per minute: 300
Requests per day: Unlimited
Requests per month: Unlimited
Concurrent requests: 50
```

---

## Feature Comparison Matrix

| Feature | Public | Registered | Professional | Enterprise |
|---------|--------|------------|--------------|------------|
| **Dashboard** |
| Threat map view | Read-only | Full | Full | Full |
| Time range controls | Last 24h | Full | Full | Full |
| Threat type filters | Limited | Full | Full | Full |
| Hotspots panel | Top 10 | Full | Full | Full |
| Indicator table | No | Yes | Yes | Yes |
| **Search & Enrichment** |
| Indicator search | No | 100/day | 10K/mo | Unlimited |
| Indicator enrichment | No | 100/day | 10K/mo | Unlimited |
| Multi-source lookup | No | Limited | Full | Full |
| Historical data | No | 7 days | 90 days | 1 year |
| **Alerts & Monitoring** |
| Watchlists | No | 5 items | 100 items | Unlimited |
| Email alerts | No | Weekly | Real-time | Real-time |
| Webhook notifications | No | No | 5 endpoints | Unlimited |
| Custom alert rules | No | No | Yes | Yes |
| **API Access** |
| REST API | No | No | Yes | Yes |
| API rate limit | - | - | 60/min | 300/min |
| Bulk operations | No | No | No | Yes |
| **Export** |
| CSV export | No | No | Yes | Yes |
| STIX 2.1 | No | No | Yes | Yes |
| MISP format | No | No | Yes | Yes |
| Blocklists (RPZ) | No | No | Yes | Yes |
| **Support** |
| Documentation | Yes | Yes | Yes | Yes |
| Email support | No | Community | 48h response | 24h response |
| Dedicated support | No | No | No | Yes |
| SLA guarantee | No | No | No | 99.9% |

---

## Payment Integration

### Primary: Stripe
- International credit cards
- Subscription management
- Invoice generation
- Tax compliance

### Secondary: Paystack
- African-focused payments
- Mobile money (M-Pesa, MTN MoMo)
- Local bank transfers
- Kenya, Nigeria, South Africa, Ghana

### Payment Flow
```
User selects tier
    │
    ├─► International card? ──► Stripe checkout
    │
    └─► African payment? ──► Paystack checkout
                │
                ├─► M-Pesa (KE)
                ├─► MTN MoMo (multiple)
                ├─► Bank transfer
                └─► Local cards
```

---

## API Key Management

### Key Format
```
jdns_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx  (Production)
jdns_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx  (Testing)
```

### Key Features
- Scoped permissions
- IP whitelist option
- Usage dashboard
- Rotation capability
- Expiration dates (optional)

### Scopes
```
read:indicators      - Search and view indicators
read:enrichment      - Detailed indicator enrichment
read:regions         - Region scores and stats
write:watchlist      - Manage watchlists
write:webhooks       - Manage webhook endpoints
export:stix          - STIX export
export:misp          - MISP export
export:blocklist     - Blocklist generation
admin:*              - Full administrative access
```

---

## Usage Metering

### Tracked Metrics
- API requests (by endpoint)
- Enrichment lookups
- Export operations
- Webhook deliveries

### Billing Logic
```python
# Monthly reset
credits_used = 0
credits_limit = subscription.monthly_quota

# Per-request tracking
def track_usage(api_key, endpoint, credits=1):
    usage = get_or_create_usage(api_key, current_month)
    usage.credits_used += credits
    
    if usage.credits_used >= credits_limit:
        raise QuotaExceededError()
```

### Overage Handling
- Professional: Hard limit, request fails
- Enterprise: Soft limit, overage billed at $0.001/request

---

## Revenue Projections

### Year 1 (Conservative)

| Tier | Users | Monthly Revenue |
|------|-------|-----------------|
| Public | 1,000+ | $0 |
| Registered | 500 | $0 |
| Professional | 30 | $1,470 |
| Enterprise | 5 | $1,495 |
| **Total Monthly** | | **$2,965** |
| **Total Annual** | | **$35,580** |

### Year 1 (Optimistic)

| Tier | Users | Monthly Revenue |
|------|-------|-----------------|
| Public | 5,000+ | $0 |
| Registered | 2,000 | $0 |
| Professional | 80 | $3,920 |
| Enterprise | 15 | $4,485 |
| **Total Monthly** | | **$8,405** |
| **Total Annual** | | **$100,860** |

---

## Go-to-Market Strategy

### Phase 1: Soft Launch (Month 1-2)
- Free public dashboard
- Invite-only Professional tier
- 10 beta Enterprise customers
- Collect feedback

### Phase 2: Public Launch (Month 3)
- Open Professional signups
- Launch marketing campaign
- Target African CERTs and banks
- Conference presentations (AfriNIC, AfricaCERT)

### Phase 3: Scale (Month 4-6)
- Partner channel development
- White-label offerings
- MSSP partnerships
- Regional expansion

---

## Target Customers

### Primary Targets

| Segment | Countries | Est. Market Size |
|---------|-----------|------------------|
| **Banks** | KE, ZA, NG, EG, MA | 200+ institutions |
| **Telecoms** | All Africa | 100+ operators |
| **Government** | All Africa | 54 countries |
| **National CERTs** | Active CERTs | 20+ organizations |

### Key Accounts to Target

**Kenya:**
- Safaricom (telecom)
- Equity Bank, KCB (banking)
- Kenya CERT

**South Africa:**
- MTN, Vodacom (telecom)
- Standard Bank, FNB, Absa (banking)
- CSIR (research)

**Nigeria:**
- MTN Nigeria, Airtel (telecom)
- GTBank, Zenith Bank (banking)
- ngCERT

**Egypt:**
- Orange Egypt, Vodafone Egypt (telecom)
- CIB, NBE (banking)
- EG-CERT

---

## Competitive Positioning

### Differentiators

| JichoDNS | Global Competitors |
|----------|-------------------|
| Africa-focused | Global (limited Africa data) |
| RIPE Atlas integration | Passive DNS only |
| Local payment options | Credit card only |
| ML for African threats | Generic models |
| Open source core | Proprietary |

### Pricing Comparison

| Platform | Similar Tier | Price |
|----------|--------------|-------|
| JichoDNS Professional | $49/mo | - |
| Recorded Future | ~$10K+/year | Enterprise only |
| Anomali | ~$5K+/year | Enterprise only |
| DomainTools | ~$99+/mo | Iris Investigate |
| SecurityTrails | ~$50/mo | API access |

---

## Terms of Service Highlights

### Fair Use Policy
- API access for security research only
- No reselling of data
- No excessive automated queries
- Attribution required for public use

### Data Retention
- Free: 7 days of personal data
- Professional: 90 days
- Enterprise: 1 year

### SLA (Enterprise)
- 99.9% uptime guarantee
- < 500ms API response (p95)
- 24h support response time
