# Profiles: build and install

Two `httpx` malleable profiles modeled on documented actor traffic. They shape Apollo's egress so
the beacon looks like a real financial-sector actor and gives Nawi a realistic detection target.

| File | Actor | Signature it reproduces |
|---|---|---|
| `lockbit-icbc.httpx.toml` | LockBit affiliate (ICBC) | 62.76s/37% jitter, GET `/_next.css` + POST `/boards`, Host `user.compdatasystems.com`, base64-x2 + 814-byte-strip tasking transform |
| `qilin-ocsp.httpx.toml` | Qilin / Agenda | Forged `Host: ocsp.verisign.com`, Microsoft-CryptoAPI UA, `application/ocsp-request` masquerade |

## Prerequisites (on the Mythic server)

```bash
# Install the httpx C2 profile container (once)
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/httpx
sudo ./mythic-cli c2 start httpx

# Apollo agent (if not already installed)
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo
```

## Build an Apollo payload with one of these profiles

In the Mythic UI: Create Payload -> OS Windows -> agent **Apollo** -> C2 profile **httpx** ->
paste the chosen `.toml` into the `raw_c2_config` build parameter (httpx accepts TOML or JSON).
Set the agent-side items the profile does not cover:

- **Callback host/port:** point at your redirector (see `../redirectors/`), not the Mythic box.
- **LockBit realism:** set injection target to `wuauclt.exe`; if using P2P, name the SMB pipe
  `fullduplex_84`.
- **Sleep/jitter:** already in the profile (`callback_interval` / `callback_jitter`), confirm the
  UI picks them up.

## The borrow pipeline (Tyche) - turn any real CS profile into a Mythic profile

```bash
git clone https://github.com/Whispergate/Tyche && cd Tyche
# From a Cobalt Strike malleable profile:
python3 tyche.py --input jquery.profile --format cobaltstrike --out mythic-httpx.json
# From a Burp-saved request or a TOML file: --format burp | toml
# Tyche can also emit nginx/apache/caddy redirector rules from the same input.
```

This is how you get from a public malleable-C2 collection
(`threatexpress/malleable-c2`, `xx0hcd/Malleable-C2-Profiles`, `rsmudge/Malleable-C2-Profiles`) or a
generator (`C2concealer`, `SourcePoint`) straight into a working `httpx` profile plus a matching
redirector, in one step. To match LockBit byte-for-byte (incl. the exact 814-byte junk prefix and
the documented User-Agent), import the source CS profile through Tyche rather than hand-editing.

## Cobalt Strike malleable -> httpx cheat sheet

| CS malleable | httpx |
|---|---|
| `http-get`/`http-post` blocks | `[get]`/`[post]` (`verb`, `uris`) |
| `set uri "/a /b";` | `uris = ["/a","/b"]` |
| `client { header "X" "Y"; }` | `[get.client] headers."X" = "Y"` |
| metadata `header "Cookie"` / `parameter "q"` | `[get.client.message] location = "cookie"\|"query"\|"header"\|"body"`, `name` |
| `base64`/`base64url`/`netbios(u)`/`mask`/`prepend`/`append` | `[[...transforms]] action = "base64"\|"base64url"\|"netbios"\|"netbiosu"\|"xor"\|"prepend"\|"append"` (CS `mask` ~ `xor`) |
| `server { output { ... } }` | `[get.server] [[get.server.transforms]]` |
| `set useragent` | `headers."User-Agent"` |
| `set sleeptime`/`set jitter` | `callback_interval`/`callback_jitter` |

Does not carry over: CS `stage`, `process-inject`, `post-ex`, `https-certificate` blocks (Mythic
handles those per-agent or at the redirector). Drop them.

## Deliberate realism gap (leave this for the JA4H lesson)

Both profiles set a browser or CryptoAPI User-Agent, but Apollo is .NET Framework, so the real
client TLS/HTTP fingerprint (JA4H) says .NET. That User-Agent-vs-JA4H mismatch is one of the
detections in `../detections/`. Real operators make exactly this mistake; keep it so Nawi can catch
it. If you want a harder run, drive a .NET-consistent UA or move to a native agent (Xenon).
