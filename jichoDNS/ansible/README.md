# JichoDNS Ansible Deployment

Production-ready deployment automation for JichoDNS. Deploys all services to a single server.

## Architecture

All services run on **one server** (23.150.68.201) via Docker:

```
                    +--[ 23.150.68.201 ]--+
                    |                     |
  :80  --> Nginx ---|---> Frontend (:3000) |
                    |---> API (:8000)      |
                    |                     |
                    | Celery Worker        |
                    | Celery Beat          |
                    |                     |
                    | PostgreSQL (:5432)   |
                    | ClickHouse (:9000)   |
                    | Redis (:6379)        |
                    | Elasticsearch (:9200)|
                    | Kibana (:5601)       |
                    +---------------------+
```

## Prerequisites

- Ansible 2.15+ installed locally
- SSH access to the target server
- Ansible Vault password (ask the team lead)

## Quick Start (Manual Deploy)

```bash
cd ansible

# 1. Create your vault password file (NEVER commit this)
echo "your-vault-password" > .vault_password
chmod 600 .vault_password

# 2. Install required Ansible collections
ansible-galaxy collection install community.docker community.general ansible.posix

# 3. Run the full deployment
ansible-playbook site.yml

# 4. Deploy only the app (skip OS setup and databases)
ansible-playbook site.yml --tags app

# 5. Deploy only databases
ansible-playbook site.yml --tags database
```

## CI/CD (GitHub Actions)

Deployment runs automatically on push to `main`. Configure these GitHub Secrets:

| Secret | Description |
|--------|-------------|
| `ANSIBLE_VAULT_PASSWORD` | Password to decrypt vault.yml |
| `SSH_PRIVATE_KEY` | Private SSH key for the deploy user |
| `DEPLOY_HOST` | Target IP: `23.150.68.201` |
| `DEPLOY_USER` | SSH user: `plover` |

Manual deploy via GitHub Actions: **Actions > Deploy JichoDNS > Run workflow**

## Secret Management

All secrets are stored in `group_vars/all/vault.yml` (AES-256 encrypted).

```bash
# View encrypted secrets
ansible-vault view group_vars/all/vault.yml

# Edit secrets
ansible-vault edit group_vars/all/vault.yml

# Re-encrypt with new password
ansible-vault rekey group_vars/all/vault.yml
```

### What's in the vault

- SSH credentials
- Database passwords (PostgreSQL, ClickHouse, Redis, Elasticsearch)
- Application secret key
- External API keys (Shodan, VirusTotal, RIPE Atlas, etc.)
- Payment provider keys (Stripe, Paystack)
- GCP project config

## File Structure

```
ansible/
  ansible.cfg              # Ansible configuration
  inventory.yml            # Server inventory
  site.yml                 # Main playbook
  .vault_password          # Vault password (GITIGNORED)
  group_vars/
    all/
      vars.yml             # Non-secret variables (committed)
      vault.yml            # Encrypted secrets (committed, safe)
  roles/
    common/                # OS hardening, firewall, fail2ban
    docker/                # Docker Engine + Compose installation
    database/              # PostgreSQL, ClickHouse, Redis, ES, Kibana
    app/                   # API, Workers, Frontend, Nginx
```

## Tags

| Tag | What it deploys |
|-----|-----------------|
| `common` | OS packages, firewall, SSH hardening |
| `docker` | Docker Engine + Compose |
| `database` | All database containers |
| `app` | API, Workers, Frontend, Nginx |
| `setup` | common + docker |
| `deploy` | app only |
| `db` | database only |

## Troubleshooting

```bash
# Check all service status on server
ssh plover@23.150.68.201 "docker ps -a"

# Check logs
ssh plover@23.150.68.201 "docker logs jichodns-api --tail 50"
ssh plover@23.150.68.201 "docker logs jichodns-frontend --tail 50"

# Restart everything
ssh plover@23.150.68.201 "cd /opt/jichodns && docker compose -f docker-compose.db.yml -f docker-compose.app.yml restart"

# Run playbook in check mode (dry run)
ansible-playbook site.yml --check --diff
```
