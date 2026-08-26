# Mythic IaC - Ansible Deployment

Unified Infrastructure-as-Code deployment for Mythic C2 framework using Ansible.

## Structure

```
ansible/
├── 0-site.yml                          # Main orchestrator playbook
├── 1-bootstrap.yml                     # SSH keys, users, sudo setup
├── 2-hardening.yml                     # UFW, fail2ban, auditd, SSH hardening
├── 3-docker.yml                        # Docker daemon setup
├── 4-services.yml                      # Mythic, httpx, socat, dnsmasq, nginx
├── 5-certs.yml                         # TLS certificates (self-signed or LE)
├── 6-monitoring.yml                    # Prometheus, Filebeat, Grafana
├── 7-verify.yml                        # Integration tests
├── inventory/
│   ├── lab.ini                         # Lab environment inventory
│   └── production.ini                  # Production environment inventory
├── group_vars/
│   ├── mythic_servers.yml              # Mythic server group variables
│   └── redirectors.yml                 # Redirector group variables
├── host_vars/
│   ├── mythic-01.yml                   # Mythic-01 specific variables
│   └── redirector-01.yml               # Redirector-01 specific variables
├── roles/
│   ├── bootstrap/                      # Bootstrap role
│   ├── hardening/                      # Hardening role
│   ├── docker/                         # Docker role
│   ├── mythic/                         # Mythic role
│   ├── redirector/                     # Redirector role
│   ├── monitoring/                     # Monitoring role
│   └── verify/                         # Verification role
└── README.md                           # This file
```

## Prerequisites

- Ansible 2.9+
- Python 3.8+
- Target hosts must be Ubuntu 20.04 LTS or later
- SSH access to target hosts with sudo privileges
- Internet connectivity for package downloads

## Inventory Setup

### Lab Environment
```bash
ansible-playbook -i inventory/lab.ini 0-site.yml
```

### Production Environment
```bash
ansible-playbook -i inventory/production.ini 0-site.yml
```

## Deployment Phases

The orchestrator playbook (0-site.yml) runs 7 phases in sequence:

### Phase 1: Bootstrap (1-bootstrap.yml)
- System package updates
- User creation (localuser/deployuser)
- SSH key setup
- Sudo configuration
- System time synchronization

### Phase 2: Hardening (2-hardening.yml)
- UFW firewall configuration
- fail2ban setup
- Auditd configuration
- SSH hardening (key-only auth, no passwords)
- Kernel hardening parameters

### Phase 3: Docker Setup (3-docker.yml)
- Docker daemon installation
- Docker repository configuration
- Daemon security hardening
- Systemd service configuration
- Base image pulls

### Phase 4: Services (4-services.yml)
- Mythic container deployment
- httpx C2 profile installation
- socat TCP/UDP relay
- dnsmasq DNS spoofing
- nginx reverse proxy

### Phase 5: TLS Certificates (5-certs.yml)
- Self-signed certificate generation (lab)
- Let's Encrypt certificate enrollment (ops)
- Certificate installation
- Automatic renewal configuration

### Phase 6: Monitoring (6-monitoring.yml)
- Prometheus time-series database
- Node Exporter metrics collection
- Filebeat log forwarding
- Grafana dashboards (optional)

### Phase 7: Verification (7-verify.yml)
- 8 integration tests:
  1. DNS resolution
  2. TLS certificate validity
  3. Mythic API health
  4. Container health
  5. Firewall rules
  6. SSH hardening
  7. Auditd status
  8. Backup configuration

## Usage

### Run Full Deployment
```bash
cd /Users/lmakonem/repos/Research/Mythic/iac/ansible
ansible-playbook -i inventory/lab.ini 0-site.yml
```

### Run Specific Phase
```bash
# Bootstrap only
ansible-playbook -i inventory/lab.ini 1-bootstrap.yml

# Hardening only
ansible-playbook -i inventory/lab.ini 2-hardening.yml

# Docker setup
ansible-playbook -i inventory/lab.ini 3-docker.yml

# Services deployment
ansible-playbook -i inventory/lab.ini 4-services.yml

# Certificate management
ansible-playbook -i inventory/lab.ini 5-certs.yml

# Monitoring setup
ansible-playbook -i inventory/lab.ini 6-monitoring.yml

# Run integration tests
ansible-playbook -i inventory/lab.ini 7-verify.yml
```

### Run with Specific Tags
```bash
# Only run security-related tasks
ansible-playbook -i inventory/lab.ini 0-site.yml --tags security

# Only run bootstrap tasks
ansible-playbook -i inventory/lab.ini 0-site.yml --tags bootstrap

# Skip containers
ansible-playbook -i inventory/lab.ini 0-site.yml --skip-tags containers
```

### Dry Run (Check Mode)
```bash
ansible-playbook -i inventory/lab.ini 0-site.yml --check
```

### Verbose Output
```bash
ansible-playbook -i inventory/lab.ini 0-site.yml -vvv
```

## Configuration

### Group Variables

#### mythic_servers.yml
- Mythic container ports and paths
- PostgreSQL configuration
- Docker image URLs
- UFW rules
- fail2ban settings
- Auditd rules
- SSH hardening parameters
- TLS certificate settings

#### redirectors.yml
- Nginx proxy configuration
- socat relay rules
- dnsmasq DNS settings
- DNS spoofing records
- TLS/SSL configuration
- Load balancing settings (ops mode)

### Host Variables

#### mythic-01.yml
- System hostname and IP
- VM resource allocation
- Mythic-specific credentials (from Vault)
- Database configuration
- Backup settings

#### redirector-01.yml
- Primary and secondary network interfaces
- Domain names for C2 operations
- DNS spoofing targets
- Load balancing configuration

## Modes

### Lab Mode
- Single Mythic server
- Self-signed TLS certificates
- No redundancy
- ~75 min deployment

### Ops Mode
- HA Mythic (PostgreSQL replication)
- Let's Encrypt TLS certificates
- Multiple redirectors with VIP
- Vault-managed secrets
- ~180 min deployment

## Verification

After deployment, verify the installation:

```bash
# Check Mythic API
curl -k https://10.23.20.10:7443/api

# Check containers
docker ps

# Check firewall
ufw status

# Check certificates
openssl x509 -in /etc/ssl/certs/mythic.crt -text -noout

# Review logs
journalctl -u mythic -f
docker logs -f mythic_mythic_1
```

## Troubleshooting

### SSH Key Issues
If SSH key authentication fails, verify:
1. Public keys are in `~/.ssh/authorized_keys`
2. Permissions are 0600 on keys and 0700 on `.ssh`
3. SELinux/AppArmor is not blocking SSH

### Docker Issues
If Docker fails to start:
1. Check systemd status: `systemctl status docker`
2. Review logs: `journalctl -u docker -f`
3. Verify daemon.json syntax: `docker config view`

### Certificate Issues
If TLS certificates fail:
1. Check certificate path: `ls -la /etc/ssl/certs/`
2. Verify expiration: `openssl x509 -in /etc/ssl/certs/mythic.crt -noout -dates`
3. Renew if expired: Run 5-certs.yml again

### Firewall Issues
If connectivity fails:
1. Check UFW status: `ufw status verbose`
2. Reload rules: `ufw reload`
3. Verify rules: `ufw show added`

## Idempotency

All playbooks are designed to be idempotent (safe to run multiple times):
- File creation/modification checks
- Service state management
- Configuration file validations
- Handlers for service restarts

## Customization

### Adding Custom Hosts
Edit `inventory/lab.ini` or `inventory/production.ini`:
```ini
[mythic_servers]
mythic-02 ansible_host=10.23.20.11 ansible_user=localuser
```

### Adding Custom Variables
Create `host_vars/mythic-02.yml`:
```yaml
hostname: mythic-02
ip_address: 10.23.20.11
```

### Adding Custom Tasks
Extend playbooks by creating new task files in roles:
```bash
roles/mythic/tasks/custom.yml
```

Then include in `roles/mythic/tasks/main.yml`:
```yaml
- include_tasks: custom.yml
```

## Scaling

### Single Mythic Server (Lab)
```bash
# Suitable for: CTF, training, POC
ansible-playbook -i inventory/lab.ini 0-site.yml
```

### HA Mythic Cluster (Ops)
```bash
# Edit inventory/production.ini to add mythic-02
# Configure PostgreSQL streaming replication
# Run production deployment
ansible-playbook -i inventory/production.ini 0-site.yml
```

### Multi-Redirector Setup
```bash
# Edit inventory/production.ini to add redirector-02, redirector-03
# Configure keepalived VIP
# Run production deployment
ansible-playbook -i inventory/production.ini 0-site.yml
```

## Testing

Run integration tests:
```bash
ansible-playbook -i inventory/lab.ini 7-verify.yml
```

Expected output:
```
Integration Test Results
========================
DNS Resolution: PASS
TLS Certificate: PASS
Mythic API Health: PASS
Container Health: PASS
Firewall (UFW): PASS
SSH Hardening: PASS
Audit Daemon (auditd): PASS
Backup Configuration: PASS
========================
```

## Maintenance

### Regular Updates
```bash
# Update system packages
ansible-playbook -i inventory/lab.ini 1-bootstrap.yml --tags updates

# Update Mythic containers
docker pull docker.io/itsafeature/mythic_mythic:latest
ansible-playbook -i inventory/lab.ini 4-services.yml --tags mythic
```

### Certificate Renewal
```bash
# Let's Encrypt auto-renewal (runs via cron)
# Manual renewal:
ansible-playbook -i inventory/production.ini 5-certs.yml
```

### Backup and Recovery
```bash
# Create backup
docker exec mythic_postgres_1 pg_dump -U mythic_user mythic > backup.sql

# Restore from backup
docker exec -i mythic_postgres_1 psql -U mythic_user mythic < backup.sql
```

## Security Considerations

1. **SSH Keys**: Use strong key-based authentication (no passwords)
2. **Secrets**: Store credentials in Vault or environment variables
3. **Firewall**: UFW is configured to deny all inbound by default
4. **Auditd**: Enabled for compliance and forensics
5. **TLS**: Certificates renewed automatically (ops mode)
6. **Logging**: Centralized logging with Filebeat

## Files Created During Deployment

```
/opt/mythic/                          # Mythic installation directory
/etc/ssl/certs/mythic.crt             # TLS certificate
/etc/ssl/private/mythic.key           # TLS private key
/var/lib/prometheus/                  # Prometheus time-series data
/var/log/mythic/                      # Application logs
/etc/audit/rules.d/mythic.rules       # Auditd rules
/opt/scripts/                         # Deployment scripts
```

## References

- Mythic C2: https://github.com/its-a-feature/Mythic
- Ansible: https://docs.ansible.com
- Proxmox: https://www.proxmox.com/docs
- Ubuntu Hardening: https://ubuntu.com/security/hardening
- Docker Security: https://docs.docker.com/engine/security/

## Support

For issues or questions:
1. Check `/tmp/mythic-deployment-logs/deployment.log`
2. Review playbook output with `-vvv` flag
3. Consult role-specific documentation in `roles/*/README.md`
