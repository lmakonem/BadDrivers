# cloudflared_router

An Ansible role to configure **Cloudflare Tunnel** on **Ludus router VMs**, so each range securely exposes its **Kali KasmVNC** instance over HTTPS via Cloudflare.

Each range router becomes a **self-contained Cloudflare connector** for its own Kali box.

---

## What This Role Does

- Installs `cloudflared` on the Ludus router VM
- Writes `/etc/cloudflared/config.yml` pointing a Cloudflare Tunnel hostname to the Kali KasmVNC HTTPS listener (`https://<kali_ip>:8444`)
- Installs a `systemd` unit for `cloudflared`
- Enables and starts the tunnel automatically at boot

---

## Requirements

- **Router VM OS**: Debian 11 or 12
- **Network access from router**:
  - TCP 443 outbound (Cloudflare Tunnel)
  - TCP 8444 to the Kali VM (KasmVNC HTTPS)
- **Cloudflare**:
  - A pre-created Cloudflare Tunnel
  - Tunnel credentials JSON (downloaded from Cloudflare Zero Trust)

---

## Role Variables

| Variable | Default | Description |
|--------|--------|-------------|
| `cloudflare_tunnel_name` | `ludus-kali-tunnel` | Tunnel name defined in Cloudflare |
| `cloudflare_hostname` | `kali-range.example.com` | Public hostname for this range’s Kali |
| `cloudflare_kali_ip` | `10.99.99.1` | Kali IP from the router’s perspective |
| `cloudflare_kali_port` | `8444` | KasmVNC HTTPS port |
| `cloudflare_credentials_file` | `/etc/cloudflared/credentials.json` | Path to tunnel credentials JSON |
| `cloudflared_package_name` | `cloudflared` | cloudflared package name |

---

## 1. Create a Cloudflare Tunnel

Example credentials JSON:

```json
{
  "AccountTag": "REPLACE_ME",
  "TunnelSecret": "REPLACE_ME",
  "TunnelID": "REPLACE_ME"
}
```

---

## 2. Add the Role to Your Ansible Project

```bash
git clone https://github.com/your_github_handle/ansible-role-cloudflared_router.git roles/cloudflared_router
```

---

## 2. Add the Role to Your Ansible Project

```text
roles/
└── cloudflared_router/
```

---

## License

MIT

