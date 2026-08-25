# Lab httpx redirector (F2) — DEPLOYED

Dedicated redirector VM for the LockBit/Qilin httpx ops profile. Terminates TLS on an
nginx/OpenSSL stack (self-signed, lab) instead of Mythic's Go listener — this is the N6 lesson.
A real Let's Encrypt cert is not obtainable in this isolated lab; the self-signed cert leaves a
cert-anomaly, which is itself a valid detection (detections N6 "cert first-seen anomalies").

| Item | Value |
|---|---|
| Proxmox | pve @ 192.168.36.225 |
| VMID / name | **117 / httpx-redir** (linked clone of template 105 ubuntu-22.04) |
| Network | **dual-homed**: net0 vmbr1023 tag=20 (10.23.20/24 upstream) + net1 vmbr0 (192.168.36/24 callback) |
| Callback IP (clients beacon here) | **192.168.36.117**/24 (ens19, static, default via 192.168.36.1) |
| Upstream IP (to Mythic) | **10.23.20.201**/24 (ens18, DHCP, connected route to 10.23.20.10) |
| Listener | nginx 1.18 on 0.0.0.0:443, self-signed `CN=assets-portal.io` |
| Upstream | `http://10.23.20.10:82` via ens18 (Mythic httpx `mythic_httpx_se`, host-net) |
| Flow | client -> 192.168.36.117:443 (nginx TLS) -> proxy over 10-side -> Mythic 10.23.20.10:82 |
| Match | LockBit profile: `GET /_next.css` + `POST /boards` with UA `Chrome/120.0.0.0 Safari/537.36` -> proxied; else 302 -> `https://www.microsoft.com/` |
| Config | `/etc/nginx/sites-available/httpx-redir` (this repo: `lab-httpx-redir.nginx.conf`); backup `/root/httpx-redir.conf.deployed` |
| Enabled on boot | yes |

## Verified at deploy
- 443 listening; upstream Mythic:82 reachable (404 = httpx responding to a non-beacon GET).
- beacon UA -> proxied; wrong UA + `/` -> 302 decoy.

## Rebuild / teardown
- Rebuild config: `scp lab-httpx-redir.nginx.conf` -> `/etc/nginx/sites-available/httpx-redir`; `nginx -t && systemctl reload nginx`.
- Teardown VM: `qm stop 117 && qm destroy 117` on pve.

## Notes / follow-ups
- SSH key injection via cloud-init did NOT take on template 105 (baked-in `ubuntu` user); the VM
  was configured via the qemu guest agent (`qm guest exec 117`). To get SSH later, fix
  authorized_keys perms or set `qm set 117 --cipassword` + regen cloud-init.
- Qilin variant: add a second server block / vhost (forged `Host: ocsp.verisign.com`) or a second
  redirector; not built yet.
- The `sardonic-redir` VM (144) is a separate raw-TCP DNAT for the Sardonic profile on 443 — do not
  conflate; that is why httpx needed its own VM.
