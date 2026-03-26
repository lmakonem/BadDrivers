# JichoDNS Database Schema

## Overview

JichoDNS uses a dual-database architecture:
- **PostgreSQL 15**: Primary transactional database for indicators, users, API keys
- **ClickHouse**: High-performance analytics database for DNS events and query logs

---

## PostgreSQL Schema

### Core Tables

#### indicators

```sql
CREATE TABLE indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    value VARCHAR(255) NOT NULL,
    value_type VARCHAR(20) NOT NULL,          -- domain, ip, url
    indicator_type VARCHAR(20) NOT NULL,      -- c2, phishing, exfil, unknown
    
    -- Source information
    source VARCHAR(100) NOT NULL,
    source_ref VARCHAR(255),                  -- External ID from source
    
    -- Classification
    malware_family VARCHAR(100),
    campaign VARCHAR(100),
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    tags TEXT[],
    
    -- Timestamps
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Metadata
    raw_data JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(value, source)
);

-- Indexes
CREATE INDEX idx_indicators_value ON indicators(value);
CREATE INDEX idx_indicators_type ON indicators(indicator_type);
CREATE INDEX idx_indicators_active ON indicators(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_indicators_first_seen ON indicators(first_seen DESC);
CREATE INDEX idx_indicators_source ON indicators(source);
CREATE INDEX idx_indicators_malware ON indicators(malware_family) WHERE malware_family IS NOT NULL;
CREATE INDEX idx_indicators_value_trgm ON indicators USING gin (value gin_trgm_ops);
CREATE INDEX idx_indicators_tags ON indicators USING gin (tags);
```

#### indicator_scores

```sql
CREATE TABLE indicator_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_id UUID NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    
    -- ML classification scores
    c2_probability FLOAT,
    exfil_probability FLOAT,
    phishing_probability FLOAT,
    benign_probability FLOAT,
    
    -- Aggregate risk score
    overall_risk_score FLOAT,
    
    -- Model metadata
    model_version VARCHAR(50),
    scored_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Feature snapshot
    features JSONB,
    
    CONSTRAINT valid_probabilities CHECK (
        (c2_probability IS NULL OR c2_probability BETWEEN 0 AND 1) AND
        (exfil_probability IS NULL OR exfil_probability BETWEEN 0 AND 1) AND
        (phishing_probability IS NULL OR phishing_probability BETWEEN 0 AND 1) AND
        (benign_probability IS NULL OR benign_probability BETWEEN 0 AND 1)
    )
);

CREATE INDEX idx_scores_indicator ON indicator_scores(indicator_id);
CREATE INDEX idx_scores_time ON indicator_scores(scored_at DESC);
CREATE INDEX idx_scores_risk ON indicator_scores(overall_risk_score DESC);
```

#### region_scores

```sql
CREATE TABLE region_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ts_bucket TIMESTAMPTZ NOT NULL,           -- 15-minute time bucket
    region_type VARCHAR(10) NOT NULL,         -- country, asn
    region_id VARCHAR(20) NOT NULL,           -- ISO code or ASN number
    region_name VARCHAR(100),
    
    -- Risk scores by threat type
    c2_risk FLOAT DEFAULT 0,
    exfil_risk FLOAT DEFAULT 0,
    phishing_risk FLOAT DEFAULT 0,
    overall_risk FLOAT DEFAULT 0,
    
    -- Counts
    indicator_count INTEGER DEFAULT 0,
    query_count INTEGER DEFAULT 0,
    probe_count INTEGER DEFAULT 0,
    
    -- Geo (for ASNs)
    latitude FLOAT,
    longitude FLOAT,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(ts_bucket, region_type, region_id)
);

CREATE INDEX idx_region_scores_bucket ON region_scores(ts_bucket DESC);
CREATE INDEX idx_region_scores_type_id ON region_scores(region_type, region_id);
CREATE INDEX idx_region_scores_risk ON region_scores(overall_risk DESC);
```

### Domain Intelligence Tables

#### domain_observations

```sql
CREATE TABLE domain_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) NOT NULL UNIQUE,
    
    -- First-seen tracking
    first_seen_dns TIMESTAMPTZ,               -- First seen in RIPE Atlas
    first_seen_feed TIMESTAMPTZ,              -- First seen in threat feed
    whois_created_at TIMESTAMPTZ,             -- WHOIS registration date
    
    -- Computed age
    domain_age_hours INTEGER GENERATED ALWAYS AS (
        EXTRACT(EPOCH FROM (NOW() - LEAST(
            COALESCE(first_seen_dns, NOW()),
            COALESCE(first_seen_feed, NOW()),
            COALESCE(whois_created_at, NOW())
        ))) / 3600
    ) STORED,
    
    -- Domain string features
    length INTEGER,
    label_count INTEGER,
    entropy FLOAT,
    has_digits BOOLEAN,
    digit_ratio FLOAT,
    consonant_ratio FLOAT,
    tld VARCHAR(20),
    
    -- Behavioral flags
    is_dga_like BOOLEAN DEFAULT FALSE,
    dga_score FLOAT,
    is_typosquat BOOLEAN DEFAULT FALSE,
    typosquat_target VARCHAR(255),
    typosquat_type VARCHAR(50),
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_domain_obs_age ON domain_observations(domain_age_hours)
    WHERE domain_age_hours < 48;
CREATE INDEX idx_domain_obs_first_seen ON domain_observations(first_seen_dns DESC);
CREATE INDEX idx_domain_obs_dga ON domain_observations(is_dga_like) WHERE is_dga_like = TRUE;
CREATE INDEX idx_domain_obs_typo ON domain_observations(is_typosquat) WHERE is_typosquat = TRUE;
```

#### whois_cache

```sql
CREATE TABLE whois_cache (
    domain VARCHAR(255) PRIMARY KEY,
    registrar VARCHAR(200),
    created_date TIMESTAMPTZ,
    updated_date TIMESTAMPTZ,
    expires_date TIMESTAMPTZ,
    registrant_country VARCHAR(2),
    registrant_org VARCHAR(200),
    name_servers TEXT[],
    status TEXT[],
    raw_whois TEXT,
    fetched_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Age calculation
    domain_age_days INTEGER GENERATED ALWAYS AS (
        CASE WHEN created_date IS NOT NULL
        THEN EXTRACT(DAY FROM (NOW() - created_date))::INTEGER
        ELSE NULL END
    ) STORED
);

CREATE INDEX idx_whois_fetched ON whois_cache(fetched_at);
CREATE INDEX idx_whois_age ON whois_cache(domain_age_days) WHERE domain_age_days < 30;
```

#### query_patterns

```sql
CREATE TABLE query_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_id UUID REFERENCES indicators(id) ON DELETE CASCADE,
    ts_bucket TIMESTAMPTZ NOT NULL,
    
    -- Query type distribution
    query_count_total INTEGER DEFAULT 0,
    query_count_a INTEGER DEFAULT 0,
    query_count_aaaa INTEGER DEFAULT 0,
    query_count_txt INTEGER DEFAULT 0,
    query_count_mx INTEGER DEFAULT 0,
    query_count_ns INTEGER DEFAULT 0,
    query_count_other INTEGER DEFAULT 0,
    
    -- Response patterns
    nxdomain_rate FLOAT,
    servfail_rate FLOAT,
    success_rate FLOAT,
    avg_ttl INTEGER,
    min_ttl INTEGER,
    max_ttl INTEGER,
    unique_answer_ips INTEGER,
    
    -- Subdomain analysis
    unique_subdomains INTEGER,
    avg_subdomain_length FLOAT,
    max_subdomain_length INTEGER,
    subdomain_entropy_avg FLOAT,
    subdomain_entropy_max FLOAT,
    
    -- Geographic distribution
    querying_countries VARCHAR(2)[],
    querying_asns INTEGER[],
    
    -- Anomaly flags
    txt_ratio_anomaly BOOLEAN DEFAULT FALSE,
    subdomain_length_anomaly BOOLEAN DEFAULT FALSE,
    query_timing_anomaly BOOLEAN DEFAULT FALSE,
    nxdomain_anomaly BOOLEAN DEFAULT FALSE,
    
    UNIQUE(indicator_id, ts_bucket)
);

CREATE INDEX idx_query_patterns_indicator ON query_patterns(indicator_id);
CREATE INDEX idx_query_patterns_bucket ON query_patterns(ts_bucket DESC);
CREATE INDEX idx_query_patterns_anomaly ON query_patterns(txt_ratio_anomaly, subdomain_length_anomaly)
    WHERE txt_ratio_anomaly OR subdomain_length_anomaly;
```

### RIPE Atlas Tables

#### probes

```sql
CREATE TABLE probes (
    id INTEGER PRIMARY KEY,                   -- RIPE Atlas probe ID
    country_code VARCHAR(2),
    asn INTEGER,
    asn_name VARCHAR(200),
    latitude FLOAT,
    longitude FLOAT,
    city VARCHAR(100),
    is_anchor BOOLEAN DEFAULT FALSE,
    status VARCHAR(20),                       -- Connected, Disconnected, etc.
    tags TEXT[],
    last_connected TIMESTAMPTZ,
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_probes_country ON probes(country_code);
CREATE INDEX idx_probes_asn ON probes(asn);
CREATE INDEX idx_probes_status ON probes(status);
```

#### atlas_measurements

```sql
CREATE TABLE atlas_measurements (
    id INTEGER PRIMARY KEY,                   -- RIPE Atlas measurement ID
    indicator_id UUID REFERENCES indicators(id) ON DELETE SET NULL,
    
    measurement_type VARCHAR(20),             -- dns, traceroute, http, tls
    target VARCHAR(255),
    query_type VARCHAR(10),                   -- A, AAAA, TXT, etc.
    
    status VARCHAR(20),                       -- Specified, Ongoing, Stopped
    start_time TIMESTAMPTZ,
    stop_time TIMESTAMPTZ,
    
    probe_count INTEGER,
    probe_countries VARCHAR(2)[],
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_measurements_indicator ON atlas_measurements(indicator_id);
CREATE INDEX idx_measurements_status ON atlas_measurements(status);
```

### Typosquatting Tables

#### typosquat_targets

```sql
CREATE TABLE typosquat_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brand_name VARCHAR(100) NOT NULL,
    legitimate_domains TEXT[] NOT NULL,
    keywords TEXT[],
    country_focus VARCHAR(2)[],
    category VARCHAR(50),                     -- banking, telecom, government, etc.
    is_active BOOLEAN DEFAULT TRUE,
    last_scanned TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Default African brands to monitor
INSERT INTO typosquat_targets (brand_name, legitimate_domains, keywords, country_focus, category) VALUES
('M-Pesa', ARRAY['safaricom.co.ke', 'mpesa.co.ke'], ARRAY['mpesa', 'm-pesa'], ARRAY['KE', 'TZ'], 'mobile_money'),
('Safaricom', ARRAY['safaricom.co.ke', 'safaricom.com'], ARRAY['safaricom'], ARRAY['KE'], 'telecom'),
('MTN', ARRAY['mtn.com', 'mtn.co.za'], ARRAY['mtn', 'mtn-momo'], ARRAY['ZA', 'NG', 'GH', 'UG'], 'telecom'),
('Airtel', ARRAY['airtel.africa', 'airtel.com'], ARRAY['airtel', 'airtel-money'], ARRAY['KE', 'NG', 'TZ', 'UG'], 'telecom'),
('Equity Bank', ARRAY['equitybankgroup.com', 'equitybank.co.ke'], ARRAY['equity', 'equitybank'], ARRAY['KE'], 'banking'),
('KCB Bank', ARRAY['kcbgroup.com', 'kcbbankgroup.com'], ARRAY['kcb', 'kcbbank'], ARRAY['KE'], 'banking'),
('Standard Bank', ARRAY['standardbank.co.za', 'standardbank.com'], ARRAY['standardbank'], ARRAY['ZA'], 'banking'),
('FNB', ARRAY['fnb.co.za'], ARRAY['fnb', 'firstnationalbank'], ARRAY['ZA'], 'banking'),
('ABSA', ARRAY['absa.co.za', 'absa.africa'], ARRAY['absa'], ARRAY['ZA', 'KE'], 'banking'),
('GTBank', ARRAY['gtbank.com'], ARRAY['gtbank', 'gtb'], ARRAY['NG'], 'banking'),
('Jumia', ARRAY['jumia.com', 'jumia.co.ke', 'jumia.com.ng'], ARRAY['jumia'], ARRAY['KE', 'NG', 'ZA'], 'ecommerce');
```

#### typosquat_detections

```sql
CREATE TABLE typosquat_detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES typosquat_targets(id) ON DELETE CASCADE,
    indicator_id UUID REFERENCES indicators(id) ON DELETE SET NULL,
    
    domain VARCHAR(255) NOT NULL,
    fuzzer_type VARCHAR(50),                  -- homoglyph, hyphenation, insertion, etc.
    similarity_score FLOAT,
    
    -- Resolution status
    is_registered BOOLEAN,
    resolves_to INET[],
    hosting_asn INTEGER,
    hosting_country VARCHAR(2),
    
    -- Risk assessment
    has_mx BOOLEAN,
    has_web BOOLEAN,
    ssl_issuer VARCHAR(200),
    
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    last_checked TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(target_id, domain)
);

CREATE INDEX idx_typo_detections_target ON typosquat_detections(target_id);
CREATE INDEX idx_typo_detections_registered ON typosquat_detections(is_registered) WHERE is_registered = TRUE;
CREATE INDEX idx_typo_detections_time ON typosquat_detections(detected_at DESC);
```

### Pattern Clustering Tables

#### pattern_clusters

```sql
CREATE TABLE pattern_clusters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_type VARCHAR(50) NOT NULL,        -- dga, campaign, infrastructure, beaconing
    name VARCHAR(200),
    description TEXT,
    
    -- Matching criteria
    pattern_regex VARCHAR(500),
    seed_indicator_id UUID REFERENCES indicators(id),
    
    -- Stats
    member_count INTEGER DEFAULT 0,
    first_seen TIMESTAMPTZ,
    last_updated TIMESTAMPTZ,
    
    -- Attribution
    malware_family VARCHAR(100),
    campaign VARCHAR(100),
    threat_actor VARCHAR(100),
    confidence VARCHAR(20),                   -- high, medium, low
    
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_clusters_type ON pattern_clusters(cluster_type);
CREATE INDEX idx_clusters_active ON pattern_clusters(is_active) WHERE is_active = TRUE;
```

#### pattern_cluster_members

```sql
CREATE TABLE pattern_cluster_members (
    cluster_id UUID REFERENCES pattern_clusters(id) ON DELETE CASCADE,
    indicator_id UUID REFERENCES indicators(id) ON DELETE CASCADE,
    confidence FLOAT,
    relationship VARCHAR(50),                 -- seed, similar_pattern, shared_infra
    added_at TIMESTAMPTZ DEFAULT NOW(),
    
    PRIMARY KEY (cluster_id, indicator_id)
);
```

### User Management Tables

#### users

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255),
    
    -- Profile
    name VARCHAR(200),
    organization VARCHAR(200),
    country VARCHAR(2),
    
    -- Auth
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    is_admin BOOLEAN DEFAULT FALSE,
    
    -- OAuth
    oauth_provider VARCHAR(50),
    oauth_id VARCHAR(255),
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

CREATE INDEX idx_users_email ON users(email);
```

#### api_subscriptions

```sql
CREATE TABLE api_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    
    tier VARCHAR(20) NOT NULL,                -- free, professional, enterprise
    status VARCHAR(20) DEFAULT 'active',      -- active, suspended, cancelled
    
    -- Limits
    monthly_quota INTEGER,
    daily_quota INTEGER,
    rate_limit_per_minute INTEGER,
    
    -- Billing
    stripe_customer_id VARCHAR(100),
    stripe_subscription_id VARCHAR(100),
    paystack_customer_code VARCHAR(100),
    paystack_subscription_code VARCHAR(100),
    
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_user ON api_subscriptions(user_id);
CREATE INDEX idx_subscriptions_status ON api_subscriptions(status);
```

#### api_keys

```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID REFERENCES api_subscriptions(id) ON DELETE CASCADE,
    
    key_hash VARCHAR(64) NOT NULL,            -- SHA-256 of API key
    key_prefix VARCHAR(12) NOT NULL,          -- jdns_live_xxx for identification
    name VARCHAR(100),
    
    -- Permissions
    scopes TEXT[],
    ip_whitelist INET[],
    
    -- Usage
    last_used_at TIMESTAMPTZ,
    last_used_ip INET,
    
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_subscription ON api_keys(subscription_id);
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = TRUE;
```

#### api_usage

```sql
CREATE TABLE api_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    ts TIMESTAMPTZ DEFAULT NOW(),
    endpoint VARCHAR(200),
    method VARCHAR(10),
    status_code INTEGER,
    response_time_ms INTEGER,
    
    -- Billing
    credits_used INTEGER DEFAULT 1,
    
    -- Context
    request_id UUID,
    user_agent VARCHAR(500),
    ip_address INET
);

-- Partition by month for performance
CREATE INDEX idx_api_usage_key ON api_usage(api_key_id, ts DESC);
CREATE INDEX idx_api_usage_ts ON api_usage(ts DESC);

-- Materialized view for dashboards
CREATE MATERIALIZED VIEW api_usage_daily AS
SELECT
    api_key_id,
    user_id,
    DATE(ts) as date,
    COUNT(*) as total_requests,
    SUM(credits_used) as total_credits,
    AVG(response_time_ms)::INTEGER as avg_response_time,
    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count
FROM api_usage
WHERE ts > NOW() - INTERVAL '90 days'
GROUP BY api_key_id, user_id, DATE(ts);
```

### User Features Tables

#### watchlists

```sql
CREATE TABLE watchlists (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    
    name VARCHAR(100),
    value VARCHAR(255) NOT NULL,
    value_type VARCHAR(20),                   -- domain, ip, asn, campaign
    notes TEXT,
    
    -- Alerts
    alert_on_change BOOLEAN DEFAULT TRUE,
    last_alert_at TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_watchlists_user ON watchlists(user_id);
```

#### webhooks

```sql
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID REFERENCES api_subscriptions(id) ON DELETE CASCADE,
    
    url VARCHAR(500) NOT NULL,
    secret VARCHAR(255),
    
    events TEXT[] NOT NULL,                   -- new_c2, new_phishing, high_risk_nod, etc.
    filters JSONB,                            -- {countries: ["KE"], min_risk: 0.7}
    
    is_active BOOLEAN DEFAULT TRUE,
    last_triggered TIMESTAMPTZ,
    failure_count INTEGER DEFAULT 0,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_webhooks_subscription ON webhooks(subscription_id);
CREATE INDEX idx_webhooks_active ON webhooks(is_active) WHERE is_active = TRUE;
```

---

## ClickHouse Schema

### atlas_events

```sql
CREATE TABLE atlas_events (
    id UUID DEFAULT generateUUIDv4(),
    ts DateTime64(3),
    
    -- Probe info
    probe_id UInt32,
    probe_cc LowCardinality(String),
    probe_asn UInt32,
    probe_city Nullable(String),
    
    -- Indicator info
    indicator_id UUID,
    indicator_value String,
    indicator_type LowCardinality(String),
    
    -- Measurement info
    measurement_id UInt32,
    measurement_type LowCardinality(String),  -- dns, traceroute, tls
    
    -- DNS specific
    dns_qname String,
    dns_qtype LowCardinality(String),
    dns_rcode Nullable(UInt8),
    dns_rtt_ms Nullable(Float32),
    dns_answer_ips Array(String),
    dns_answer_count Nullable(UInt8),
    dns_ttl Nullable(UInt32),
    dns_dnssec_ok Nullable(UInt8),
    
    -- Traceroute specific
    tr_hop_count Nullable(UInt8),
    tr_path_asns Array(UInt32),
    tr_total_rtt_ms Nullable(Float32),
    tr_destination_reached Nullable(UInt8),
    
    -- TLS/HTTP specific
    tls_cert_issuer Nullable(String),
    tls_cert_subject Nullable(String),
    http_status Nullable(UInt16),
    http_server Nullable(String),
    
    -- Raw data
    raw_result String,
    
    -- Indexes
    INDEX idx_indicator_value indicator_value TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_probe_cc probe_cc TYPE set(0) GRANULARITY 1,
    INDEX idx_indicator_type indicator_type TYPE set(0) GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, probe_cc, indicator_id)
TTL ts + INTERVAL 90 DAY;
```

### dns_query_details

```sql
CREATE TABLE dns_query_details (
    ts DateTime64(3),
    
    -- Probe
    probe_id UInt32,
    probe_cc LowCardinality(String),
    probe_asn UInt32,
    
    -- Query
    qname String,
    qtype LowCardinality(String),
    
    -- Parsed
    domain String,                            -- Registered domain
    subdomain String,
    subdomain_length UInt16,
    subdomain_entropy Float32,
    
    -- Response
    rcode UInt8,
    answer_count UInt8,
    answer_ips Array(String),
    ttl UInt32,
    rtt_ms Float32,
    
    -- Flags
    is_encoded_subdomain UInt8,
    has_high_entropy UInt8
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, domain, probe_cc)
TTL ts + INTERVAL 30 DAY;
```

### Materialized Views

```sql
-- Hourly aggregates per domain
CREATE MATERIALIZED VIEW query_stats_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, domain)
AS SELECT
    toStartOfHour(ts) AS hour,
    domain,
    
    count() AS total_queries,
    countIf(qtype = 'A') AS queries_a,
    countIf(qtype = 'AAAA') AS queries_aaaa,
    countIf(qtype = 'TXT') AS queries_txt,
    countIf(qtype = 'MX') AS queries_mx,
    
    countIf(rcode = 0) AS success_count,
    countIf(rcode = 3) AS nxdomain_count,
    countIf(rcode = 2) AS servfail_count,
    
    uniq(subdomain) AS unique_subdomains,
    avg(subdomain_length) AS avg_subdomain_length,
    max(subdomain_length) AS max_subdomain_length,
    avg(subdomain_entropy) AS avg_subdomain_entropy,
    
    uniq(probe_asn) AS unique_asns,
    groupUniqArray(probe_cc) AS countries,
    
    avg(rtt_ms) AS avg_rtt,
    avg(ttl) AS avg_ttl
FROM dns_query_details
GROUP BY hour, domain;

-- Country-level daily stats
CREATE MATERIALIZED VIEW country_stats_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, country)
AS SELECT
    toDate(ts) AS day,
    probe_cc AS country,
    
    count() AS total_queries,
    uniq(domain) AS unique_domains,
    uniq(probe_asn) AS unique_asns,
    
    countIf(has_high_entropy = 1) AS high_entropy_queries
FROM dns_query_details
GROUP BY day, country;
```

---

## Migrations

Use Alembic for PostgreSQL migrations:

```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

---

## Performance Considerations

### PostgreSQL
- Use `pg_trgm` extension for text search on indicator values
- Partition `api_usage` table by month if needed
- Create covering indexes for common queries
- Use connection pooling (PgBouncer)

### ClickHouse
- Partition by month (toYYYYMM)
- TTL for automatic data expiration
- Use materialized views for common aggregations
- LowCardinality for enum-like columns
