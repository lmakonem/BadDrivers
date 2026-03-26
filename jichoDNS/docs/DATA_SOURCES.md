# JichoDNS Data Sources

## Overview

JichoDNS aggregates data from multiple threat intelligence sources to provide comprehensive DNS threat visibility. This document details each integration.

---

## Your Account-Based Sources

### RIPE Atlas

| Attribute | Details |
|-----------|---------|
| **URL** | https://atlas.ripe.net/ |
| **Purpose** | Active DNS measurements from African probes |
| **Access** | Your existing account |
| **Rate Limits** | Based on credits |
| **Integration** | `ripe-atlas-cousteau` Python library |

**What we measure:**
- DNS A/AAAA lookups for indicators
- DNS TXT queries (for exfiltration detection)
- Optional: Traceroute, HTTP/TLS checks

**Probe selection:**
- Target probes in African countries
- Prioritize probes in major ASNs (Safaricom, MTN, etc.)
- Minimum 3 probes per country for coverage

**Configuration:**
```python
RIPE_ATLAS_API_KEY = "your_api_key"
RIPE_ATLAS_PROBE_COUNTRIES = ["KE", "ZA", "NG", "EG", "GH", "TZ", "UG", "ET"]
RIPE_ATLAS_PROBES_PER_COUNTRY = 5
RIPE_ATLAS_MEASUREMENT_INTERVAL = 900  # 15 minutes
```

---

### Shodan

| Attribute | Details |
|-----------|---------|
| **URL** | https://shodan.io/ |
| **Purpose** | Infrastructure intelligence |
| **Access** | Membership level |
| **Rate Limits** | Web: unlimited, API: reasonable use |
| **Integration** | `shodan` Python library |

**What we collect:**
- IP details for indicator infrastructure
- Open ports and services
- SSL certificates
- Hostnames and reverse DNS
- Historical data

**Useful queries:**
```python
# Find DNS servers in Africa
shodan.search("port:53 country:KE")

# Find open resolvers
shodan.search("port:53 Recursion: enabled country:ZA")

# Infrastructure for suspicious domain
shodan.host("185.234.x.x")

# Certificate hunting
shodan.search("ssl.cert.subject.cn:safaricom")
```

**Configuration:**
```python
SHODAN_API_KEY = "your_api_key"
SHODAN_CACHE_TTL = 86400  # 24 hours
```

---

### Vertex AI

| Attribute | Details |
|-----------|---------|
| **URL** | https://cloud.google.com/vertex-ai |
| **Purpose** | ML model inference |
| **Access** | Your GCP account |
| **Rate Limits** | Usage-based billing |
| **Integration** | Google Cloud AI Platform SDK |

**Model details:**
- Input: Feature vector + domain string
- Output: Class probabilities (C2, Exfil, Phishing, Benign)
- Model: Fine-tuned transformer (HuggingFace-based)

**Configuration:**
```python
GOOGLE_APPLICATION_CREDENTIALS = "/path/to/credentials.json"
VERTEX_AI_PROJECT = "your-project-id"
VERTEX_AI_LOCATION = "us-central1"
VERTEX_AI_ENDPOINT = "endpoint-id"
```

---

## Free Threat Intelligence Feeds

### Abuse.ch URLhaus

| Attribute | Details |
|-----------|---------|
| **URL** | https://urlhaus.abuse.ch/ |
| **Data Type** | Malware distribution URLs |
| **Format** | JSON, CSV |
| **Update Frequency** | Every 5 minutes |
| **Rate Limits** | Fair use policy |
| **Priority** | Tier 1 - Essential |

**API Endpoints:**
```
GET https://urlhaus-api.abuse.ch/v1/urls/recent/
GET https://urlhaus-api.abuse.ch/v1/url/  (POST with url parameter)
GET https://urlhaus-api.abuse.ch/v1/host/ (POST with host parameter)
```

**Bulk download:**
```
https://urlhaus.abuse.ch/downloads/json_recent/
https://urlhaus.abuse.ch/downloads/csv_recent/
```

**Data fields:**
- URL
- URL status (online/offline)
- Threat type
- Tags (malware names)
- First seen
- Last seen
- Hosting details

---

### Abuse.ch ThreatFox

| Attribute | Details |
|-----------|---------|
| **URL** | https://threatfox.abuse.ch/ |
| **Data Type** | IOCs with malware family attribution |
| **Format** | JSON |
| **Update Frequency** | Real-time |
| **Rate Limits** | Fair use, API key required |
| **Priority** | Tier 1 - Essential |

**API Endpoints:**
```
POST https://threatfox-api.abuse.ch/api/v1/
```

**Query types:**
- `get_iocs` - Recent IOCs
- `search_ioc` - Search specific IOC
- `search_hash` - Search by malware hash
- `taginfo` - Get tag information

**Data fields:**
- IOC type (domain, ip:port, url)
- Threat type (botnet_cc, payload_delivery)
- Malware family (linked to Malpedia)
- Confidence level
- First/last seen
- Tags

**Configuration:**
```python
THREATFOX_API_KEY = "your_api_key"
THREATFOX_POLL_INTERVAL = 300  # 5 minutes
```

---

### Abuse.ch Feodo Tracker

| Attribute | Details |
|-----------|---------|
| **URL** | https://feodotracker.abuse.ch/ |
| **Data Type** | Banking trojan C2 servers |
| **Format** | JSON, CSV, various blocklist formats |
| **Update Frequency** | Continuous |
| **Rate Limits** | None |
| **Priority** | Tier 1 - Essential |

**Tracked malware:**
- Dridex
- Emotet
- TrickBot
- QakBot
- BazarLoader

**Download URLs:**
```
https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json
https://feodotracker.abuse.ch/downloads/domainblocklist.json
```

---

### Abuse.ch SSL Blacklist

| Attribute | Details |
|-----------|---------|
| **URL** | https://sslbl.abuse.ch/ |
| **Data Type** | Malicious SSL certificates, JA3 fingerprints |
| **Format** | CSV, JSON |
| **Update Frequency** | Continuous |
| **Rate Limits** | None |
| **Priority** | Tier 2 |

**Download URLs:**
```
https://sslbl.abuse.ch/blacklist/sslblacklist.csv
https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
```

---

### PhishTank

| Attribute | Details |
|-----------|---------|
| **URL** | https://phishtank.org/ |
| **Data Type** | Verified phishing URLs |
| **Format** | XML, CSV, JSON, PHP serialized |
| **Update Frequency** | Hourly |
| **Rate Limits** | API key required |
| **Priority** | Tier 1 - Essential |

**API Endpoint:**
```
GET http://data.phishtank.com/data/{api_key}/online-valid.json.gz
```

**Data fields:**
- URL
- Phish ID
- Target brand
- Verification time
- Online status

**Configuration:**
```python
PHISHTANK_API_KEY = "your_api_key"
```

---

### AlienVault OTX

| Attribute | Details |
|-----------|---------|
| **URL** | https://otx.alienvault.com/ |
| **Data Type** | Community IOCs, pulses |
| **Format** | JSON |
| **Update Frequency** | Real-time |
| **Rate Limits** | 10,000 API calls/day |
| **Priority** | Tier 1 - Essential |

**API Base URL:**
```
https://otx.alienvault.com/api/v1/
```

**Useful endpoints:**
```
GET /pulses/subscribed          # Your subscribed pulses
GET /indicators/domain/{domain} # Domain details
GET /indicators/IPv4/{ip}       # IP details
GET /pulses/search?q={query}    # Search pulses
```

**Configuration:**
```python
OTX_API_KEY = "your_api_key"
```

---

### VirusTotal

| Attribute | Details |
|-----------|---------|
| **URL** | https://www.virustotal.com/ |
| **Data Type** | Multi-engine reputation |
| **Format** | JSON |
| **Update Frequency** | Real-time |
| **Rate Limits** | Free: 4/min, 500/day |
| **Priority** | Tier 1 - Essential |

**API v3 Endpoints:**
```
GET /api/v3/domains/{domain}
GET /api/v3/ip_addresses/{ip}
GET /api/v3/urls/{id}
```

**Data we extract:**
- Detection count
- Categories
- WHOIS data
- Passive DNS (last_dns_records)
- Resolutions history
- Communicating files

**Configuration:**
```python
VIRUSTOTAL_API_KEY = "your_api_key"
VIRUSTOTAL_CACHE_TTL = 3600  # 1 hour (to respect limits)
```

---

### AbuseIPDB

| Attribute | Details |
|-----------|---------|
| **URL** | https://www.abuseipdb.com/ |
| **Data Type** | IP reputation |
| **Format** | JSON |
| **Update Frequency** | Real-time |
| **Rate Limits** | Free: 1,000/day |
| **Priority** | Tier 1 - Essential |

**API Endpoints:**
```
GET /api/v2/check?ipAddress={ip}
GET /api/v2/blacklist
```

**Data fields:**
- Abuse confidence score (0-100)
- Total reports
- Last reported
- ISP/ASN details
- Usage type

**Configuration:**
```python
ABUSEIPDB_API_KEY = "your_api_key"
```

---

## Infrastructure Data Sources

### crt.sh (Certificate Transparency)

| Attribute | Details |
|-----------|---------|
| **URL** | https://crt.sh/ |
| **Data Type** | SSL certificates |
| **Format** | JSON |
| **Update Frequency** | Real-time |
| **Rate Limits** | Moderate rate limiting |
| **Priority** | Tier 2 |

**Query format:**
```
https://crt.sh/?q={domain}&output=json
https://crt.sh/?q=%.{domain}&output=json  # Subdomains
```

**Use cases:**
- Find related domains via certificates
- Identify infrastructure changes
- Track certificate issuance patterns

---

### Team Cymru IP-to-ASN

| Attribute | Details |
|-----------|---------|
| **URL** | https://www.team-cymru.com/ip-asn-mapping |
| **Data Type** | IP to ASN mapping |
| **Format** | Text |
| **Update Frequency** | Every 4 hours |
| **Rate Limits** | None |
| **Priority** | Tier 2 |

**Query methods:**
```bash
# DNS-based lookup
dig +short 1.2.3.4.origin.asn.cymru.com TXT

# WHOIS-based lookup
whois -h whois.cymru.com " -v 1.2.3.4"

# Bulk via netcat
netcat whois.cymru.com 43 < ip_list.txt
```

---

### RIPEstat

| Attribute | Details |
|-----------|---------|
| **URL** | https://stat.ripe.net/ |
| **Data Type** | BGP/routing data, ASN info |
| **Format** | JSON |
| **Update Frequency** | Real-time |
| **Rate Limits** | Fair use |
| **Priority** | Tier 2 |

**Useful data calls:**
```
GET /data/prefix-overview/data.json?resource={prefix}
GET /data/as-overview/data.json?resource={asn}
GET /data/routing-history/data.json?resource={prefix}
GET /data/geoloc/data.json?resource={ip}
```

---

### BGPView

| Attribute | Details |
|-----------|---------|
| **URL** | https://bgpview.io/ |
| **Data Type** | ASN information |
| **Format** | JSON |
| **Update Frequency** | Near real-time |
| **Rate Limits** | None documented |
| **Priority** | Tier 3 |

**API Endpoints:**
```
GET /api/asn/{asn}
GET /api/asn/{asn}/prefixes
GET /api/ip/{ip}
GET /api/prefix/{prefix}
```

---

## Africa-Specific DNS Data Sources

These sources provide unique Africa-focused DNS intelligence that differentiates JichoDNS from global platforms.

### African DNS Observatory

| Attribute | Details |
|-----------|---------|
| **URL** | https://observatory.dnsstudy.africa/ |
| **Purpose** | African ccTLD zone statistics and DNSSEC monitoring |
| **Coverage** | 63 African TLDs (38 DNSSEC-signed) |
| **Data Type** | Domain counts, DNSSEC status, zone statistics |
| **Update Frequency** | Varies by ccTLD (some continuous, some periodic) |
| **Access** | Public web interface |
| **Priority** | Tier 1 - Essential for Africa focus |

**Data available:**
- Domain counts per African ccTLD (2.4M+ domains tracked)
- DNSSEC signing status per TLD
- Registrar distribution
- Domain registration trends
- IDN (Internationalized Domain Names) support

**African TLDs tracked:**
```
Central: cm, cf, cg, cd, ga, st
East: bi, ke (111K domains), rw, ss, tz (56K), ug
North: dz, dj, eg, er, et, ly, ma (20K), so, sd, tn
South: ao, bw (15K), ls, mw, mz, za (1.9M!), sz, zm, zw (71K)
West: bj, bf, cv, td, gq, gm, gh, gn, gw, ci, lr, ml, mr, ne, ng (22K), sn, sl, tg
gTLDs: .africa, .capetown, .durban, .joburg
```

**Integration approach:**
- Scrape for zone statistics (with permission/partnership)
- Monitor DNSSEC adoption trends
- Track new domain registrations in African TLDs
- Correlate with threat indicators

**Contact for partnership:** info@dnsstudy.africa

---

### ISC RIPE Atlas Visualization (atlas-vis.isc.org)

| Attribute | Details |
|-----------|---------|
| **URL** | https://atlas-vis.isc.org/ |
| **Purpose** | Global DNS root server query visualization |
| **Data Type** | Root server query patterns, anycast distribution |
| **Update Frequency** | Real-time |
| **Access** | Public |
| **Priority** | Tier 2 - Context for DNS infrastructure |

**What it shows:**
- Root server query distribution by IPv4/IPv6
- Geographic distribution of DNS root queries
- Root server instance locations
- Query patterns by root letter (A-M)

**Relevance for JichoDNS:**
- Understand baseline DNS behavior in African regions
- Identify anomalies in root query patterns
- Context for infrastructure analysis

---

### Root Server Technical Operations (root-servers.org)

| Attribute | Details |
|-----------|---------|
| **URL** | https://root-servers.org/ |
| **Purpose** | Root server locations and status |
| **Data Type** | Root server instance locations, RSSAC002 data |
| **Format** | JSON, YAML |
| **Access** | Public API |
| **Priority** | Tier 2 |

**Root server instances in Africa (selected):**
```
D-Root (UMD): Accra GH, Addis Ababa ET, Arusha TZ, Cape Town ZA,
              Dar es Salaam TZ, Johannesburg ZA, Kampala UG,
              Kigali RW, Lagos NG, Mombasa KE, Nairobi KE, etc.
              
E-Root (NASA): Accra GH, Antananarivo MG, Arusha TZ, Cape Town ZA,
               Casablanca MA, Johannesburg ZA, etc.
               
K-Root (RIPE NCC): Extensive African presence
```

**API Endpoints:**
```
GET https://root-servers.org/root/{letter}/json/
GET https://root-servers.org/root/{letter}/yaml/
```

**Data fields:**
- Operator info
- IPv4/IPv6 addresses
- ASN
- Instance locations (city, country)
- Site type (Global/Local)

---

### RSSAC002 Statistics

| Attribute | Details |
|-----------|---------|
| **URL** | https://rssac002.root-servers.org/ |
| **Purpose** | Root server operational statistics |
| **Data Type** | Query volumes, response times, error rates |
| **Format** | JSON, CSV |
| **Access** | Public |
| **Priority** | Tier 3 |

**Metrics available:**
- Traffic volume by root server
- Query types distribution
- Response latency
- DNSSEC validation rates

---

### DNS-OARC Tools

| Attribute | Details |
|-----------|---------|
| **URL** | https://github.com/DNS-OARC |
| **Purpose** | DNS analysis and research tools |
| **License** | Various open source |
| **Priority** | Tier 2 - Tools for analysis |

**Relevant tools (now on Codeberg):**
- **dnscap**: DNS packet capture
- **dsc**: DNS Statistics Collector
- **dnsperf**: DNS performance testing
- **PacketQ**: SQL queries on DNS packets

**Use cases:**
- Analyze DNS traffic patterns
- Performance benchmarking
- Deep packet inspection for anomalies

---

## Open Source Tools

### DNSTwist

| Attribute | Details |
|-----------|---------|
| **URL** | https://github.com/elceef/dnstwist |
| **Purpose** | Typosquatting detection |
| **License** | Apache-2.0 |
| **Integration** | Python library or subprocess |

**Usage:**
```python
import dnstwist

# Generate permutations and check registration
results = dnstwist.run(
    domain='safaricom.co.ke',
    registered=True,
    format='null'
)

for r in results:
    if r.get('dns_a'):
        print(f"Found: {r['domain']} -> {r['dns_a']}")
```

**Fuzzers available:**
- Homoglyph
- Hyphenation
- Insertion
- Omission
- Repetition
- Replacement
- Transposition
- Vowel-swap
- Addition
- Dictionary-based

---

## Data Normalization

All indicators are normalized to a common schema:

```python
{
    "id": "uuid",
    "value": "domain or IP",
    "type": "domain | ip | url",
    "indicator_type": "c2 | phishing | exfil | unknown",
    "source": "threatfox | urlhaus | phishtank | ...",
    "confidence": 0-100,
    "first_seen": "ISO datetime",
    "last_seen": "ISO datetime",
    "malware_family": "emotet | trickbot | ...",
    "campaign": "optional campaign ID",
    "tags": ["tag1", "tag2"],
    "raw_data": { /* original feed data */ }
}
```

---

## Feed Update Schedule

| Feed | Frequency | Method |
|------|-----------|--------|
| URLhaus | Every 5 min | Bulk download |
| ThreatFox | Every 5 min | API poll |
| Feodo Tracker | Every 15 min | Bulk download |
| PhishTank | Hourly | API download |
| AlienVault OTX | Every 10 min | API subscription |
| VirusTotal | On-demand | API (cached) |
| AbuseIPDB | On-demand | API (cached) |
| RIPE Atlas | Continuous | Measurement results |
| Shodan | On-demand | API (cached) |
