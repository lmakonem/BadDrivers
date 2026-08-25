# TASK F1 — Sardonic / FIN8 binary payload type (Track 2)   [SCAFFOLD ONLY]

**Status:** not started (scaffold). Do not implement the wire protocol in the remediation pass.
**Interim action already applied (F9/F1):** the mis-named `fin8_cdn` httpx config was renamed to
`generic_cdn_beacon` so it is **not miscounted as FIN8 coverage**. FIN8/Sardonic is a non-TLS
binary protocol on TCP/443 and is **not representable in httpx** — it requires a custom
PayloadType + C2-profile build.

## Scope
Build a Mythic custom agent + C2 profile that reproduces the FIN8 Sardonic wire shape at the
traffic level (emulation, not real malware): plaintext **binary framing on TCP/443 with no TLS**,
12-byte little-endian header `[size][flags (4 = client->server)][opcode]`, optional RC4 session key
RSA-wrapped with the public OpenSSL test cert, three-server priority fallback with a ~50-min wait
if 443 is closed. This is the genuine Mythic agent-dev exercise; the goal is that a FIN8-tuned
analytic catches it, i.e. the detection surface is exercised.

## Public references (work from these)
- Bitdefender, *FIN8 Sardonic backdoor* / *BADHATCH* technical analyses (protocol, header, opcodes,
  RSA-with-OpenSSL-test-key, sslip.io).
- Mythic PayloadType developer docs: https://docs.mythic-c2.net (agent + C2 profile container model).
- Existing scaffold in this repo: `track2-sardonic-agent/` (payload_type/, c2_profile/, implant/,
  iac/) — currently untracked; put it under version control when Track 2 work begins.
- MITRE ATT&CK G0061 (FIN8).

## Milestones
1. C2-profile container: TCP listener + 12-byte binary framing translation to Mythic REST.
2. PayloadType container: build params (3-server fallback list, RC4 toggle), command modules.
3. Implant: header/opcode state machine, RSA-wrap-with-OpenSSL-test-key key exchange (captures
   decryptable by design — forensics lesson), priority fallback + wait.
4. sslip.io wildcard egress option (A-B-C-D.sslip.io -> A.B.C.D).
5. Full-chain run + Atomic Red Team unit tests.

## Acceptance detection
A **non-TLS binary flow on TCP/443** that a FIN8-tuned analytic catches, e.g. a 443 flow the Zeek
`ssl` analyzer cannot parse as TLS (no ClientHello / JA3 absent where a handshake is expected),
plus the RSA-wrapped-with-known-key handshake being decryptable from capture. New analytic to be
authored under `detections/` (none exists yet for the binary-on-443 shape).
