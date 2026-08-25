# Detections: the Nawi / Elastic + Sysmon payoff

Detections keyed to the two profiles and the Apollo agent, so the emulation is a real teaching
target for the Nawi SOC. Field names are Elastic ECS; queries are pseudo-EQL / ES|QL / KQL to adapt,
not drop-in rules. Pair with Atomic Red Team to unit-test each one before the full-chain run.

## Run the two-run exercise

- **Run 1 (baseline):** Apollo on the default `http` profile. The blue team should win on static
  fingerprints (default JARM, default `index`/`data` URIs, default named pipes). Confirm Nawi fires.
- **Run 2 (hardened):** Apollo on `lockbit-icbc.httpx.toml` behind the Let's Encrypt nginx
  redirector with the 62s/37% sleep. The static signatures should go dark, forcing the behavioral
  detections below. "Which detections survived Run 2?" is the exercise.

## Network detections

### N1. JA4H (HTTP client) vs User-Agent mismatch  [highest fidelity for Mythic]
Apollo is .NET Framework, so its HTTP-client fingerprint is a .NET runtime, but both profiles claim
a browser / CryptoAPI UA. That disagreement is the strongest network catch.
```
network where http.request.headers.user-agent like ("*Chrome*", "*CryptoAPI*")
  and http.ja4h in ("<dotnet-fw-ja4h-values-baseline-from-your-own-apollo-build>")
```
Baseline the .NET JA4H by capturing your own Apollo beacon once, then alert on that fingerprint
carrying a non-.NET User-Agent.

### N2. Beacon periodicity over a long window (RITA-style)
62.76s sleep with 37% jitter still scores as periodic across a long sample. Jitter perturbs the
interval, not the population rhythm.
```
from logs-network_traffic.flow
| where destination.domain == "user.compdatasystems.com" or destination.domain like "*.ocsp.*"
| stats cv = stddev(inter_arrival_s)/avg(inter_arrival_s),
        size_cv = stddev(source.bytes)/avg(source.bytes), hits = count() by source.ip, destination.ip
| where cv < 0.4 and size_cv < 0.25 and hits >= 200
```
Lengthen the window to counter the long, high-jitter sleep.

### N3. Rare destination + low URI cardinality
```
from logs-network_traffic.http
| stats uris = count_distinct(url.path), srcs = count_distinct(source.ip), hits = count()
    by destination.domain
| where uris <= 3 and srcs <= 4 and hits >= 200
```
Enrich `destination.domain` against a first-seen/prevalence list: new + low-prevalence + few URIs
is the signal.

### N4. LockBit profile specifics
- Alert on GET `/_next.css` + POST `/boards` from the **same source** to the same host within a
  short window (the two-URI CS chokepoint):
  ```
  sequence by source.ip, destination.domain with maxspan=5m
    [network where url.path == "/_next.css" and http.request.method == "GET"]
    [network where url.path == "/boards"    and http.request.method == "POST"]
  ```
- Host-header / SNI / destination-IP ASN disagreement: `http.request.headers.host ==
  "user.compdatasystems.com"` but the destination IP's ASN is a VPS/hosting provider, not the ASN
  that domain's real A record resolves to.

### N5. Qilin OCSP-spoof specifics
Real OCSP goes from a cert-validation client to a real CA responder IP. This beacon does not.
```
network where (http.request.headers.host == "ocsp.verisign.com"
               or http.request.headers.user-agent like "*Microsoft-CryptoAPI*"
               or http.request.mime_type == "application/ocsp-request")
  and not destination.ip in (<known-CA-OCSP-responder-ip-ranges>)
```
Bonus host-side pivot: OCSP-shaped traffic whose owning process is not a browser, `svchost`, or a
known cert-checking binary (correlate with Sysmon 3 + process.name).

### N6. TLS infrastructure
- Run 1 easy wins: default Mythic listener JARM/JA3S (non-browser Go/Python stack) + self-signed
  cert -> Shodan/Censys/Zeek `ssl.log`. This is why Run 2 puts a real LE cert on the redirector.
- Cert first-seen anomalies; JA3S/JARM that matches no known CDN/web-server population.

## Host detections (Sysmon + Elastic Defend)

### H1. Apollo in-memory .NET (`execute_assembly` / `inline_assembly`)
```
sequence by process.entity_id with maxspan=1m
  [library where dll.name in ("clr.dll","clrjit.dll","mscoree.dll")]   # Sysmon 7
  [any where not file.extension in ("dll","exe") ]                     # no .NET assembly on disk
```
Also alert on AMSI/ETW patch detections (Apollo auto-patches both) and on an **ETW CLR-event gap**
for a process that just loaded the CLR.

### H2. Anomalous named pipe (SMB P2P)
```
file where event.action in ("PipeCreated","PipeConnected")            # Sysmon 17/18
  and not file.name in (<host known-good pipe baseline>)
```
High-severity exact matches: LockBit `fullduplex_84`; CS defaults `msagent_*`, `postex_*`,
`status_*`, `MSSE-*-server`.

### H3. Injection into wuauclt (LockBit) + beacon
```
sequence by host.id with maxspan=1m
  [process where event.action == "CreateRemoteThread" and process.target.name == "wuauclt.exe"]  # Sysmon 8
  [network where event.action == "connection_attempted" and not process.code_signature.trusted]  # Sysmon 3
```

### H4. Unsigned beacon
Sysmon 1 with `process.code_signature.trusted == false` correlated with periodic Sysmon 3 to an
external host (feeds N2).

### H5. Memory scan
Enable Elastic Defend `shellcode_collect_sample` / `memory_scan_collect_sample`; hunt
`process.Ext.memory_region.bytes_compressed_present: true` and run YARA over collected regions.

## Blind spot to demonstrate on stream

BOF (Beacon Object File) commands via Apollo/`forge` generate essentially no host or SIEM
telemetry. Detection only reappears when the operator falls back to `cmd.exe`/PowerShell (Windows
4688 command line, 4104 script-block). Run a BOF, show Nawi stays quiet, then run the same action
via a shell and show it light up. That contrast is the lesson.

## Scripting the storyline

Use the **CTID FIN7** (or FIN6) adversary-emulation plan to drive the whole kill chain over Apollo,
so the detections above fire in a realistic sequence rather than in isolation:
`github.com/center-for-threat-informed-defense/adversary_emulation_library`.
