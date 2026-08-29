# local-nana

Local Proxmox deployment of the NANA red team platform. Mirrors the AWS redteam-nana deployment with minimal differences. Replaces DEMETER/FELINE with Kassandra, installed via mythic-cli.

## Architecture

```
192.168.36.51 (redirector-1, nginx)
      |  :80/:443
      v
192.168.36.50 (mythic-server, httpx container :80)
      |  RabbitMQ/internal
      v
   Kassandra agent containers
```

## Differences from redteam-nana (AWS)

| Aspect | redteam-nana (AWS) | local-nana (Proxmox) |
|---|---|---|
| Infra | Manual EC2 | OpenTofu + Ansible |
| Network | 10.0.2.x + public DNS | 192.168.36.x |
| Agent | DEMETER (remote dev, MSVC) | Kassandra (mythic-cli install) |
| C2 profile | jwt_c2 / b64_jwt_c2 | httpx |
| Cred store | HC Vault | Trilium 192.168.36.191:8080 |
| Build VM | MalDev-Alpha (Windows EC2) | Not required (Kassandra builds in Docker) |

## Deployment order

1. `cd iac/opentofu && tofu init && tofu apply`
2. `cd iac/ansible && ansible-playbook -i inventory/lab.ini site.yml`
3. Hand-off: deploy Kassandra per the operator runbook below

## Kassandra hand-off (fully automated by Ansible)

Kassandra is installed and running after `ansible-playbook site.yml` completes. No manual steps needed.

The Ansible `kassandra` role:
1. Installs the Mythic `http` C2 profile via mythic-cli
2. Syncs `kassandra_local_path` (default: `/Users/lmakonem/repos/kassandra-mythic`) into InstalledServices
3. Enforces `panic = "abort"` in `Cargo.toml` (see Known Issues below)
4. Rebuilds the Kassandra Docker image and starts the container
5. Waits for RabbitMQ registration (KassandraTranslator in same container)

Verify: https://192.168.36.50:7443 (mythic_admin / see `.env` on .50)

## Building a payload

In the Mythic UI, create a Kassandra payload with:
- C2: http, callback_host = `http://192.168.36.51`, port 80
- no_console: True (GUI, OPSEC-safe)
- busywork_intensity: medium (or off for lab debug)

## Known Issues and Fixes

### Kassandra crashes on Windows immediately (ntdll.dll, exception 0xc000026f)

**Symptom:** Payload exits instantly. No callback. APPCRASH in ntdll.dll at the same offset
every run. Redirector logs show no requests from the target.

**Root cause:** MinGW cross-compiled Rust with `windows_subsystem = "windows"` (the
`no_console` feature) fails during process init. DWARF2 exception-handling registers
before Rust's unwind tables are ready under `WinMainCRTStartup`, causing ntdll to abort.

**Fix:** `panic = "abort"` in `[profile.release]` of `Kassandra/agent_code/kassandra/Cargo.toml`.
This removes unwind tables entirely; the GUI binary starts cleanly.

The IaC Ansible role enforces this via `lineinfile` after every source sync, so it
cannot regress. The fix is also committed to the kassandra-mythic source at `ae5e57c`.

**Verified:** 10-minute stable callback from GUI payload on WIN11-22H2-X64 (2026-08-29).

### KassandraTranslator "not connected" error on first build

The KassandraTranslator runs in the same container as Kassandra (both registered in
`main.py`). If the container exits (e.g., during a build), restart it:

```bash
cd /opt/mythic && docker compose up -d kassandra
```

### Docker compose context case mismatch

`mythic-cli install folder` writes `context: InstalledServices/kassandra` (lowercase) but
the actual directory is `InstalledServices/Kassandra` (capital K). The Ansible role fixes
this with `sed -i 's|InstalledServices/kassandra|InstalledServices/Kassandra|g'`.
