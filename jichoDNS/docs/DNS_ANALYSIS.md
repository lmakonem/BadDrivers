# JichoDNS Advanced DNS Analysis Features

## Overview

This document details the advanced DNS analysis capabilities of JichoDNS, including:
- DNS over HTTPS (DoH) / DNS over TLS (DoT) detection
- New DNS record monitoring (< 24 hours)
- Domain entropy and linguistic analysis
- DGA (Domain Generation Algorithm) detection
- Encrypted DNS abuse detection

---

## 1. DNS Protocol Monitoring

### Supported DNS Query Types

JichoDNS monitors and analyzes all standard DNS record types:

| Record Type | Purpose | Threat Relevance |
|-------------|---------|------------------|
| **A** | IPv4 address | C2, hosting infrastructure |
| **AAAA** | IPv6 address | C2, IPv6-based evasion |
| **TXT** | Text records | **Data exfiltration**, verification |
| **MX** | Mail servers | Phishing infrastructure |
| **NS** | Name servers | DNS hijacking, delegation |
| **CNAME** | Canonical names | CDN abuse, redirection |
| **SOA** | Start of authority | Zone enumeration |
| **PTR** | Reverse DNS | Infrastructure mapping |
| **SRV** | Service records | Service enumeration |
| **CAA** | Certificate authority | SSL/TLS infrastructure |
| **DNSKEY** | DNSSEC keys | DNSSEC validation |
| **DS** | Delegation signer | DNSSEC chain |
| **HTTPS/SVCB** | Service binding | DoH server detection |

### DNS over HTTPS (DoH) Detection

**Threat Context:**
- Attackers use DoH to bypass traditional DNS monitoring
- C2 traffic hidden in HTTPS connections to legitimate DoH providers
- Exfiltration via DoH queries to attacker-controlled resolvers

**Detection Methods:**

```python
# 1. Known DoH Provider Monitoring
DOH_PROVIDERS = [
    # Major public providers
    "dns.google",
    "cloudflare-dns.com", "one.one.one.one",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard.com",
    # Suspicious/uncommon providers (higher risk)
    "doh.*.onion",  # Tor-based DoH
    # Custom/unknown DoH endpoints
]

# 2. HTTPS record detection (RFC 9460)
# HTTPS/SVCB records advertise DoH capability
# Query: _dns.resolver.example.com HTTPS
# Response indicates DoH support

# 3. Port 443 DNS-like traffic patterns
# Detect encoded DNS queries in HTTPS POST bodies
```

**API Endpoint:** `GET /dns/doh-activity`

**Response:**
```json
{
  "doh_activity": {
    "period": "24h",
    "total_indicators_using_doh": 45,
    "by_provider": [
      {"provider": "cloudflare-dns.com", "queries": 1234, "risk": "low"},
      {"provider": "unknown-doh.xyz", "queries": 56, "risk": "high"}
    ],
    "suspicious_patterns": [
      {
        "indicator": "malware-c2.xyz",
        "doh_provider": "custom-resolver.attacker.com",
        "reason": "Non-standard DoH endpoint",
        "risk_score": 0.89
      }
    ]
  }
}
```

### DNS over TLS (DoT) Detection

**Port:** 853 (TCP)

**Detection via Shodan:**
```python
# Find DoT servers
shodan.search("port:853 ssl")

# Find DoT servers in Africa
shodan.search("port:853 ssl country:KE")
```

**Monitoring Points:**
- New DoT servers appearing in African ASNs
- Indicators resolving via non-standard DoT servers
- Certificate analysis for DoT endpoints

### DNS over QUIC (DoQ) Detection

**Port:** 8853 (UDP, experimental) or 443

**Emerging threat:** QUIC-based DNS provides even more obfuscation.

---

## 2. New DNS Record Monitoring (< 24 Hours)

### Purpose

Detect newly created DNS infrastructure before it appears in threat feeds.

**Key Insight:** Most malicious domains are used within 24-72 hours of registration. Early detection provides crucial lead time.

### Data Sources for New Record Detection

| Source | What We Get | Latency |
|--------|-------------|---------|
| RIPE Atlas | First resolution from our probes | Real-time |
| Certificate Transparency | New SSL certs issued | ~Minutes |
| Passive DNS partners | First seen in wild | ~Hours |
| Zone file access | New registrations | ~Daily |
| African DNS Observatory | African TLD zones | Varies |

### New Record Tracking Schema

```sql
CREATE TABLE new_dns_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Record details
    domain VARCHAR(255) NOT NULL,
    record_type VARCHAR(10) NOT NULL,  -- A, AAAA, TXT, MX, etc.
    record_value TEXT NOT NULL,
    ttl INTEGER,
    
    -- Timing
    first_seen_utc TIMESTAMPTZ NOT NULL,
    first_seen_source VARCHAR(50),  -- atlas, ct_log, passive_dns, zone_file
    age_hours FLOAT GENERATED ALWAYS AS (
        EXTRACT(EPOCH FROM (NOW() - first_seen_utc)) / 3600
    ) STORED,
    
    -- Analysis flags
    is_new_domain BOOLEAN,  -- Domain itself is new (not just record)
    is_new_ip BOOLEAN,      -- IP has never been seen before
    
    -- Risk indicators
    domain_entropy FLOAT,
    has_impossible_ngrams BOOLEAN,
    is_dga_like BOOLEAN,
    typosquat_score FLOAT,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    INDEX idx_new_records_age (age_hours) WHERE age_hours < 48
);
```

### API Endpoint: New Records

`GET /dns/records/new`

**Parameters:**
```
max_age_hours: 24           # Records newer than this
record_type: A,AAAA,TXT     # Filter by type
min_risk: 0.5               # Minimum risk score
country: KE                 # Queried from this country
```

**Response:**
```json
{
  "period": "24h",
  "total_new_records": 4567,
  "high_risk_count": 234,
  
  "by_record_type": {
    "A": 2345,
    "AAAA": 456,
    "TXT": 890,
    "MX": 234,
    "NS": 123,
    "CNAME": 519
  },
  
  "notable_records": [
    {
      "domain": "qhxzpvnm.xyz",
      "record_type": "A",
      "record_value": "185.234.x.x",
      "first_seen": "2026-03-16T10:00:00Z",
      "age_hours": 2.5,
      "risk_score": 0.94,
      "risk_signals": [
        "impossible_ngrams: qh, xz",
        "high_entropy: 4.2",
        "new_tld: xyz",
        "bulletproof_hosting"
      ]
    },
    {
      "domain": "safaricom-verify.com",
      "record_type": "A",
      "record_value": "91.215.x.x",
      "first_seen": "2026-03-16T08:00:00Z",
      "age_hours": 4.5,
      "risk_score": 0.91,
      "risk_signals": [
        "typosquat: safaricom.co.ke",
        "new_domain",
        "suspicious_registrar"
      ]
    }
  ],
  
  "new_ips_detected": [
    {
      "ip": "185.234.x.x",
      "first_seen": "2026-03-16T09:00:00Z",
      "domains_hosted": 12,
      "asn": 12345,
      "country": "RU",
      "risk_score": 0.87
    }
  ]
}
```

---

## 3. Domain Entropy & Linguistic Analysis

### Shannon Entropy Calculation

**Formula:**
```
H(X) = -Σ p(x) * log2(p(x))
```

**Implementation:**
```python
import math
from collections import Counter

def calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy of domain string."""
    # Remove TLD for analysis
    domain_part = domain.rsplit('.', 1)[0].replace('.', '')
    
    if not domain_part:
        return 0.0
    
    # Calculate character frequency
    freq = Counter(domain_part)
    length = len(domain_part)
    
    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    
    return round(entropy, 3)

# Examples:
# "google" -> 2.25 (low entropy, normal)
# "facebook" -> 2.75 (low entropy, normal)
# "qhxzpvnm" -> 3.0 (high entropy, suspicious)
# "a8f2k9x1m4" -> 3.32 (very high, likely DGA)
```

**Entropy Thresholds:**
| Entropy | Classification | Examples |
|---------|---------------|----------|
| < 2.5 | Normal | google, amazon, facebook |
| 2.5 - 3.5 | Suspicious | xyzbank-login, cdn-update-check |
| 3.5 - 4.0 | Likely DGA | qhxzpvnm, a8f2k9m1 |
| > 4.0 | Almost certainly malicious | Random 16+ char strings |

### Impossible N-gram Detection

**Linguistic Analysis:** English (and most languages) have character combinations that never occur naturally.

**Impossible Bigrams (2-letter combinations):**
```python
IMPOSSIBLE_BIGRAMS = {
    # Never occur in English
    'qh', 'qx', 'qz', 'qk', 'qv', 'qj',
    'xz', 'xq', 'xj',
    'zx', 'zq', 'zj',
    'jx', 'jz', 'jq',
    'vx', 'vz', 'vq', 'vj',
    'kx', 'kz', 'kq',
    'wx', 'wz', 'wq',
    'fq', 'fx', 'fz',
    'gx', 'gq',
    'hx', 'hz',
    'bx', 'bz', 'bq',
    'px', 'pz',
    'mx', 'mz', 'mq',
    'dx', 'dz',
    'sx', 'sz',
    'cx', 'cz', 'cq',
    # Extremely rare (flag but lower confidence)
    'uu', 'ii', 'aa',
    'qq', 'xx', 'zz',
}

# Rare trigrams
IMPOSSIBLE_TRIGRAMS = {
    'qhx', 'xzq', 'zqx', 'jqx', 'vxz',
    'xyz',  # Note: xyz is common in domain names but rare in words
}
```

**Implementation:**
```python
def detect_impossible_ngrams(domain: str) -> dict:
    """Detect linguistically impossible character combinations."""
    domain_part = domain.rsplit('.', 1)[0].replace('.', '').lower()
    
    found_bigrams = []
    found_trigrams = []
    
    # Check bigrams
    for i in range(len(domain_part) - 1):
        bigram = domain_part[i:i+2]
        if bigram in IMPOSSIBLE_BIGRAMS:
            found_bigrams.append(bigram)
    
    # Check trigrams
    for i in range(len(domain_part) - 2):
        trigram = domain_part[i:i+3]
        if trigram in IMPOSSIBLE_TRIGRAMS:
            found_trigrams.append(trigram)
    
    return {
        "has_impossible_ngrams": len(found_bigrams) > 0 or len(found_trigrams) > 0,
        "impossible_bigrams": found_bigrams,
        "impossible_trigrams": found_trigrams,
        "ngram_score": len(found_bigrams) * 0.3 + len(found_trigrams) * 0.5
    }

# Examples:
# "qhxzbank.com" -> {"has_impossible_ngrams": true, "impossible_bigrams": ["qh", "xz"]}
# "google.com" -> {"has_impossible_ngrams": false, "impossible_bigrams": []}
```

### Vowel/Consonant Ratio Analysis

**Normal English:** ~40% vowels, ~60% consonants

```python
def analyze_vowel_ratio(domain: str) -> dict:
    """Analyze vowel/consonant ratio for anomaly detection."""
    vowels = set('aeiou')
    domain_part = domain.rsplit('.', 1)[0].replace('.', '').lower()
    
    vowel_count = sum(1 for c in domain_part if c in vowels)
    consonant_count = sum(1 for c in domain_part if c.isalpha() and c not in vowels)
    total_alpha = vowel_count + consonant_count
    
    if total_alpha == 0:
        return {"vowel_ratio": 0, "is_anomalous": True}
    
    vowel_ratio = vowel_count / total_alpha
    
    # Normal range: 0.3 - 0.5
    is_anomalous = vowel_ratio < 0.15 or vowel_ratio > 0.6
    
    return {
        "vowel_count": vowel_count,
        "consonant_count": consonant_count,
        "vowel_ratio": round(vowel_ratio, 3),
        "is_anomalous": is_anomalous,
        "anomaly_type": "too_few_vowels" if vowel_ratio < 0.15 else 
                       "too_many_vowels" if vowel_ratio > 0.6 else None
    }

# DGA domains often have very low vowel ratios:
# "qhxzpvnm" -> vowel_ratio: 0.0 (ANOMALOUS)
# "google" -> vowel_ratio: 0.5 (normal)
```

### Digit Pattern Analysis

```python
def analyze_digit_patterns(domain: str) -> dict:
    """Detect suspicious digit patterns in domains."""
    domain_part = domain.rsplit('.', 1)[0].replace('.', '')
    
    digits = [c for c in domain_part if c.isdigit()]
    digit_ratio = len(digits) / len(domain_part) if domain_part else 0
    
    # Check for patterns
    has_sequential = False
    has_repeated = False
    
    for i in range(len(domain_part) - 2):
        substr = domain_part[i:i+3]
        if substr.isdigit():
            # Sequential: 123, 234, etc.
            if int(substr[1]) == int(substr[0]) + 1 and int(substr[2]) == int(substr[1]) + 1:
                has_sequential = True
            # Repeated: 111, 222, etc.
            if substr[0] == substr[1] == substr[2]:
                has_repeated = True
    
    return {
        "digit_count": len(digits),
        "digit_ratio": round(digit_ratio, 3),
        "has_sequential_digits": has_sequential,
        "has_repeated_digits": has_repeated,
        "is_suspicious": digit_ratio > 0.4 or has_sequential or has_repeated
    }
```

---

## 4. DGA (Domain Generation Algorithm) Detection

### DGA Characteristics

| Characteristic | Detection Method |
|----------------|------------------|
| High entropy | Shannon entropy > 3.5 |
| Impossible n-grams | Bigram/trigram analysis |
| No dictionary words | Dictionary lookup |
| Fixed length patterns | Length distribution analysis |
| Numeric suffixes | Regex patterns |
| Low vowel ratio | < 15% vowels |

### Known DGA Patterns

```python
DGA_FAMILIES = {
    "emotet": {
        "length_range": (8, 15),
        "tlds": ["com", "net", "org"],
        "pattern": "consonant-heavy random",
        "seed_based": True
    },
    "qakbot": {
        "length_range": (10, 20),
        "tlds": ["com", "net", "org", "info"],
        "pattern": "alphanumeric random",
        "seed_based": True
    },
    "necurs": {
        "length_range": (6, 12),
        "tlds": varies,
        "pattern": "wordlist + random",
        "seed_based": True
    },
    "banjori": {
        "length_range": (8, 12),
        "tlds": ["com"],
        "pattern": "pure random",
        "seed_based": False
    }
}
```

### DGA Detection Algorithm

```python
def detect_dga(domain: str) -> dict:
    """Comprehensive DGA detection."""
    domain_part = domain.rsplit('.', 1)[0].replace('.', '').lower()
    tld = domain.rsplit('.', 1)[1] if '.' in domain else ''
    
    # Calculate all features
    entropy = calculate_entropy(domain)
    ngrams = detect_impossible_ngrams(domain)
    vowels = analyze_vowel_ratio(domain)
    digits = analyze_digit_patterns(domain)
    
    # Dictionary word check
    has_dictionary_words = contains_dictionary_words(domain_part)
    
    # Length analysis
    length = len(domain_part)
    typical_dga_length = 8 <= length <= 20
    
    # Calculate DGA score (0-1)
    score = 0.0
    signals = []
    
    # High entropy
    if entropy > 4.0:
        score += 0.3
        signals.append(f"very_high_entropy:{entropy}")
    elif entropy > 3.5:
        score += 0.2
        signals.append(f"high_entropy:{entropy}")
    elif entropy > 3.0:
        score += 0.1
        signals.append(f"elevated_entropy:{entropy}")
    
    # Impossible n-grams
    if ngrams["has_impossible_ngrams"]:
        score += 0.25
        signals.append(f"impossible_ngrams:{ngrams['impossible_bigrams']}")
    
    # Low vowel ratio
    if vowels["vowel_ratio"] < 0.15:
        score += 0.2
        signals.append(f"low_vowel_ratio:{vowels['vowel_ratio']}")
    
    # No dictionary words
    if not has_dictionary_words:
        score += 0.15
        signals.append("no_dictionary_words")
    
    # Typical DGA length
    if typical_dga_length and not has_dictionary_words:
        score += 0.1
        signals.append(f"typical_dga_length:{length}")
    
    # Cap at 1.0
    score = min(score, 1.0)
    
    # Determine likely family based on patterns
    likely_family = match_dga_family(domain_part, tld, entropy, length)
    
    return {
        "is_dga": score > 0.5,
        "dga_score": round(score, 3),
        "confidence": "high" if score > 0.7 else "medium" if score > 0.5 else "low",
        "signals": signals,
        "likely_family": likely_family,
        "features": {
            "entropy": entropy,
            "impossible_ngrams": ngrams,
            "vowel_analysis": vowels,
            "digit_analysis": digits,
            "has_dictionary_words": has_dictionary_words,
            "length": length
        }
    }
```

### DGA Clustering

Group related DGA domains by pattern similarity:

```sql
CREATE TABLE dga_clusters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Cluster identification
    cluster_name VARCHAR(100),
    likely_family VARCHAR(50),
    
    -- Pattern characteristics
    avg_entropy FLOAT,
    avg_length FLOAT,
    common_tlds TEXT[],
    generation_seed VARCHAR(100),  -- If known
    
    -- Members
    member_count INTEGER DEFAULT 0,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    threat_level VARCHAR(20)  -- critical, high, medium, low
);

CREATE TABLE dga_cluster_members (
    cluster_id UUID REFERENCES dga_clusters(id),
    indicator_id UUID REFERENCES indicators(id),
    
    similarity_score FLOAT,
    added_at TIMESTAMPTZ DEFAULT NOW(),
    
    PRIMARY KEY (cluster_id, indicator_id)
);
```

---

## 5. Subdomain Analysis for Exfiltration Detection

### Encoded Subdomain Detection

**Threat:** Data exfiltration via DNS uses encoded data in subdomain queries:
```
aGVsbG8gd29ybGQ=.data.evil.com  (Base64: "hello world")
68656c6c6f.data.evil.com        (Hex: "hello")
```

**Detection:**
```python
import base64
import re

def analyze_subdomain_encoding(fqdn: str) -> dict:
    """Detect encoded data in subdomains."""
    parts = fqdn.split('.')
    if len(parts) < 3:
        return {"has_encoding": False}
    
    subdomain = parts[0]
    results = {
        "subdomain": subdomain,
        "length": len(subdomain),
        "encodings_detected": []
    }
    
    # Check for Base64
    if re.match(r'^[A-Za-z0-9+/]+=*$', subdomain) and len(subdomain) >= 8:
        try:
            decoded = base64.b64decode(subdomain + '==').decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 3:
                results["encodings_detected"].append({
                    "type": "base64",
                    "decoded_sample": decoded[:50],
                    "confidence": 0.9
                })
        except:
            pass
    
    # Check for Hex
    if re.match(r'^[0-9a-fA-F]+$', subdomain) and len(subdomain) >= 8 and len(subdomain) % 2 == 0:
        try:
            decoded = bytes.fromhex(subdomain).decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 3:
                results["encodings_detected"].append({
                    "type": "hex",
                    "decoded_sample": decoded[:50],
                    "confidence": 0.85
                })
        except:
            pass
    
    # Check for Base32
    if re.match(r'^[A-Z2-7]+=*$', subdomain.upper()) and len(subdomain) >= 8:
        try:
            decoded = base64.b32decode(subdomain.upper() + '====').decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 3:
                results["encodings_detected"].append({
                    "type": "base32",
                    "decoded_sample": decoded[:50],
                    "confidence": 0.85
                })
        except:
            pass
    
    results["has_encoding"] = len(results["encodings_detected"]) > 0
    return results
```

### Subdomain Length Distribution

Normal subdomains: 3-15 characters (www, mail, api, etc.)
Exfiltration: 30-63 characters (max DNS label length)

```python
def analyze_subdomain_length_distribution(domain: str, queries: list) -> dict:
    """Analyze subdomain length patterns for a domain."""
    lengths = [len(q.split('.')[0]) for q in queries]
    
    if not lengths:
        return {"has_anomaly": False}
    
    avg_length = sum(lengths) / len(lengths)
    max_length = max(lengths)
    long_subdomains = sum(1 for l in lengths if l > 30)
    
    return {
        "avg_length": round(avg_length, 2),
        "max_length": max_length,
        "long_subdomain_count": long_subdomains,
        "long_subdomain_ratio": long_subdomains / len(lengths),
        "has_anomaly": avg_length > 25 or long_subdomains / len(lengths) > 0.1,
        "likely_exfiltration": avg_length > 30 and long_subdomains / len(lengths) > 0.5
    }
```

---

## 6. API Endpoints for DNS Analysis

### Domain Linguistic Analysis

`GET /analysis/domain/{domain}/linguistic`

**Response:**
```json
{
  "domain": "qhxzbank-login.xyz",
  
  "entropy_analysis": {
    "shannon_entropy": 3.89,
    "normalized_entropy": 0.85,
    "classification": "suspicious"
  },
  
  "ngram_analysis": {
    "has_impossible_bigrams": true,
    "impossible_bigrams": ["qh", "xz"],
    "has_impossible_trigrams": false,
    "ngram_risk_score": 0.6
  },
  
  "vowel_analysis": {
    "vowel_ratio": 0.18,
    "is_anomalous": true,
    "anomaly_type": "too_few_vowels"
  },
  
  "digit_analysis": {
    "digit_ratio": 0.0,
    "has_suspicious_patterns": false
  },
  
  "dictionary_analysis": {
    "contains_words": ["bank", "login"],
    "word_ratio": 0.4,
    "remaining_random": "qhxz"
  },
  
  "dga_assessment": {
    "is_dga": true,
    "dga_score": 0.78,
    "likely_family": "unknown",
    "confidence": "high"
  },
  
  "overall_risk": {
    "score": 0.85,
    "classification": "likely_malicious",
    "signals": [
      "impossible_ngrams",
      "high_entropy",
      "low_vowel_ratio",
      "partial_dga_pattern"
    ]
  }
}
```

### New DNS Records

`GET /dns/records/new`

(See Section 2 above for full response)

### Exfiltration Detection

`GET /analysis/domain/{domain}/exfiltration`

**Response:**
```json
{
  "domain": "data-exfil.evil.com",
  "period": "24h",
  
  "subdomain_analysis": {
    "unique_subdomains": 456,
    "avg_length": 38,
    "max_length": 63,
    "avg_entropy": 4.1
  },
  
  "encoding_detection": {
    "base64_detected": 89,
    "hex_detected": 12,
    "unknown_encoding": 355,
    "decoded_samples": [
      {"subdomain": "aGVsbG8gd29ybGQ=", "decoded": "hello world", "encoding": "base64"}
    ]
  },
  
  "query_patterns": {
    "txt_ratio": 0.78,
    "query_rate_per_hour": 45,
    "is_beaconing": true,
    "beacon_interval_seconds": 300
  },
  
  "data_volume_estimate": {
    "bytes_in_subdomains": 17328,
    "queries_24h": 456,
    "estimated_exfil_rate_kb_hour": 0.72
  },
  
  "verdict": {
    "is_exfiltration": true,
    "confidence": 0.94,
    "evidence": [
      "High subdomain length (38 avg)",
      "Base64 encoding detected",
      "TXT query ratio 26x baseline",
      "Regular beaconing pattern"
    ]
  }
}
```

### DGA Detection

`GET /analysis/dga/clusters`

**Response:**
```json
{
  "active_clusters": 5,
  
  "clusters": [
    {
      "id": "cluster-emotet-2026-03",
      "name": "Emotet March 2026 Campaign",
      "likely_family": "emotet",
      "threat_level": "critical",
      
      "pattern": {
        "avg_length": 12.3,
        "avg_entropy": 3.8,
        "common_tlds": ["com", "net"],
        "vowel_ratio_range": [0.08, 0.15]
      },
      
      "indicators": {
        "total": 89,
        "active": 67,
        "samples": ["qhxzpvnm.com", "jklmnpqr.net", "bnmwerty.com"]
      },
      
      "geographic_impact": {
        "countries": ["KE", "ZA", "NG"],
        "query_count": 2345
      },
      
      "timeline": {
        "first_seen": "2026-03-10T00:00:00Z",
        "last_seen": "2026-03-16T12:00:00Z",
        "peak_activity": "2026-03-14T08:00:00Z"
      }
    }
  ]
}
```

---

## 7. Database Schema Additions

```sql
-- Domain linguistic features
ALTER TABLE domain_observations ADD COLUMN IF NOT EXISTS
    -- Entropy
    entropy FLOAT,
    entropy_classification VARCHAR(20),  -- normal, suspicious, dga_like
    
    -- N-gram analysis
    has_impossible_bigrams BOOLEAN DEFAULT FALSE,
    impossible_bigrams TEXT[],
    
    -- Vowel analysis
    vowel_ratio FLOAT,
    vowel_anomaly BOOLEAN DEFAULT FALSE,
    
    -- DGA assessment
    is_dga_like BOOLEAN DEFAULT FALSE,
    dga_score FLOAT,
    dga_family VARCHAR(50),
    dga_cluster_id UUID REFERENCES dga_clusters(id);

-- New DNS record tracking
CREATE TABLE IF NOT EXISTS new_dns_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) NOT NULL,
    record_type VARCHAR(10) NOT NULL,
    record_value TEXT NOT NULL,
    ttl INTEGER,
    
    first_seen_utc TIMESTAMPTZ NOT NULL,
    first_seen_source VARCHAR(50),
    
    -- Quick risk flags
    risk_score FLOAT,
    risk_signals TEXT[],
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_new_records_seen ON new_dns_records(first_seen_utc DESC);
CREATE INDEX idx_new_records_risk ON new_dns_records(risk_score DESC) WHERE risk_score > 0.5;

-- DoH/DoT activity tracking
CREATE TABLE IF NOT EXISTS encrypted_dns_activity (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    indicator_id UUID REFERENCES indicators(id),
    protocol VARCHAR(10),  -- doh, dot, doq
    provider VARCHAR(255),
    
    is_standard_provider BOOLEAN,
    risk_level VARCHAR(20),
    
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    query_count INTEGER DEFAULT 0
);
```

---

## 8. Configuration Options

```python
# DNS Analysis Configuration
DNS_ANALYSIS_CONFIG = {
    # Entropy thresholds
    "entropy": {
        "normal_max": 2.5,
        "suspicious_max": 3.5,
        "dga_threshold": 4.0
    },
    
    # N-gram detection
    "ngrams": {
        "check_bigrams": True,
        "check_trigrams": True,
        "custom_impossible_bigrams": [],  # Add custom patterns
    },
    
    # Vowel analysis
    "vowels": {
        "min_normal_ratio": 0.25,
        "max_normal_ratio": 0.55
    },
    
    # DGA detection
    "dga": {
        "min_score_threshold": 0.5,
        "cluster_similarity_threshold": 0.7,
        "known_families": ["emotet", "qakbot", "necurs", "banjori"]
    },
    
    # Exfiltration detection
    "exfiltration": {
        "subdomain_length_threshold": 30,
        "txt_ratio_threshold": 0.1,
        "encoding_detection": True
    },
    
    # New record monitoring
    "new_records": {
        "max_age_hours": 24,
        "high_risk_age_hours": 6,
        "monitor_record_types": ["A", "AAAA", "TXT", "MX", "NS", "CNAME"]
    },
    
    # Encrypted DNS
    "encrypted_dns": {
        "monitor_doh": True,
        "monitor_dot": True,
        "monitor_doq": True,
        "known_providers": [
            "dns.google", "cloudflare-dns.com", "dns.quad9.net"
        ]
    }
}
```

---

## Summary: Complete DNS Analysis Capabilities

| Capability | Status | Priority |
|------------|--------|----------|
| Standard DNS record monitoring (A, AAAA, etc.) | MVP | P0 |
| TXT query analysis for exfiltration | MVP | P0 |
| New DNS record tracking (< 24h) | MVP | P0 |
| Domain entropy calculation | MVP | P0 |
| Impossible n-gram detection | MVP | P0 |
| Vowel/consonant ratio analysis | MVP | P1 |
| DGA detection and scoring | MVP | P0 |
| DGA family matching | MVP | P1 |
| DGA clustering | Post-MVP | P2 |
| Encoded subdomain detection | MVP | P0 |
| DoH provider monitoring | MVP | P1 |
| DoT server detection | Post-MVP | P2 |
| DoQ monitoring | Post-MVP | P3 |
| DNSSEC validation tracking | Post-MVP | P2 |
