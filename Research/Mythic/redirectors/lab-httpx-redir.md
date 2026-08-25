# Lab httpx redirector (F2) — DEPLOYED

Dedicated redirector VM for the LockBit/Qilin httpx ops profile. Terminates TLS on an
nginx/OpenSSL stack (self-signed, lab) instead of Mythic's Go listener — this is the N6 lesson.
A real Let's Encrypt cert is not obtainable in this isolated lab; the self-signed cert leaves a
cert-anomaly, which is itself a valid detection (detections N6 "cert first-seen anomalies").

| Item | Value |
|---|---|
| Proxmox | pve @ 192.168.36.225 |
| VMID / name | **117 / httpx-redir** (linked clone of template 105 ubuntu-22.04) |
| Network | vmbr1023 **tag=20** (the 10.23.20.0/24 C2 VLAN, same as Mythic) |
| IP | **10.23.20.201** (DHCP, gw 10.23.20.254) |
| Listener | nginx 1.18 on 0.0.0.0:443, self-signed `CN=assets-portal.io` |
| Upstream | `http://10.23.20.10:82` (Mythic httpx `mythic_httpx_se`, host-net) |
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
