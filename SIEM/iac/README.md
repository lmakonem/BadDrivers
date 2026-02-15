# SOCFortress CoPilot SIEM/SOAR Infrastructure as Code

Complete Infrastructure as Code (IaC) deployment for SOCFortress CoPilot SIEM/SOAR stack across 3 VMs with MISP threat intelligence integration.

## Architecture

```
+---------------------------+
|   SOCFortress CoPilot     |  <-- PRIMARY UI
|   https://VM3:443         |
|   (Single Pane of Glass)  |
+---------------------------+
           |
+----------+----------+----------+
|          |          |          |
v          v          v          v
+--------+ +--------+ +--------+ +--------+
| Wazuh  | | Graylog| | MISP   | | Velo-  |
| Manager| | (Logs) | | (Intel)| | raptor |
+--------+ +--------+ +--------+ +--------+
           |          |
           v          v
+-----------------------------------------------+
|            Wazuh Indexer (OpenSearch)         |
|              VM1: SIEM-Data                   |
+-----------------------------------------------+
```

## VMs

| VM | Hostname | IP | Role | Services |
|----|----------|-----|------|----------|
| VM1 | SIEM-Data | 172.16.0.83 | Data Layer | Wazuh Indexer, MongoDB |
| VM2 | SIEM-CoPilot-Detect | 172.16.0.53 | Detection | Wazuh Manager, Graylog, MISP, Shuffle |
| VM3 | SIEM-CoPilot-Mgmt | 172.16.0.86 | Management | CoPilot, Grafana, Velociraptor |

## Quick Start

### Prerequisites

- Ansible 2.14+
- Python 3.9+
- SSH access to target VMs
- Docker installed on target VMs

### Deploy

```bash
# Deploy entire stack
./scripts/deploy.sh all

# Deploy specific VM
./scripts/deploy.sh vm1
./scripts/deploy.sh vm2
./scripts/deploy.sh vm3

# Dry run
./scripts/deploy.sh -c all

# Verbose output
./scripts/deploy.sh -v all
```

## Directory Structure

```
iac/
├── ansible/
│   ├── inventory/
│   │   └── hosts.yml           # Target hosts
│   ├── group_vars/
│   │   └── all.yml             # Global variables & credentials
│   ├── roles/
│   │   ├── common/             # Base system configuration
│   │   ├── docker/             # Docker installation
│   │   ├── wazuh-indexer/      # OpenSearch deployment
│   │   ├── wazuh-manager/      # Wazuh Manager + Dashboard
│   │   ├── graylog/            # Graylog + OpenSearch
│   │   ├── misp/               # MISP threat intelligence
│   │   ├── copilot/            # SOCFortress CoPilot
│   │   ├── grafana/            # Grafana dashboards
│   │   └── velociraptor/       # DFIR tool
│   └── site.yml                # Master playbook
├── docker-compose/
│   ├── vm1-siem-data.yml
│   ├── vm2-siem-detect.yml
│   └── vm3-siem-mgmt.yml
├── graylog/
│   ├── pipelines/              # Detection pipelines
│   ├── extractors/             # Field extractors
│   └── inputs/                 # Input configurations
├── grafana/
│   └── dashboards/             # Dashboard JSON files
├── integrations/
│   ├── meraki/                 # Meraki firewall integration
│   └── misp/                   # MISP feed configuration
├── scripts/
│   └── deploy.sh               # Deployment script
└── README.md
```

## Access URLs

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| CoPilot | https://172.16.0.86 | admin / Admin123! |
| Wazuh Dashboard | https://172.16.0.53:5601 | admin / SecretPassword123! |
| Graylog | http://172.16.0.53:9000 | admin / admin |
| Grafana | http://172.16.0.86:3000 | admin / GrafanaPass123! |
| MISP | https://172.16.0.53:8443 | admin@siem.local / MispAdmin123! |
| Velociraptor | https://172.16.0.86:8889 | admin / VelociraptorAdmin123! |
| Shuffle | http://172.16.0.53:3001 | (API key in CoPilot) |

## Features

### MISP Threat Intelligence
- 93 threat intel feeds (abuse.ch, Spamhaus, CIRCL, etc.)
- 1.2M+ IOCs automatically synced
- GeoIP enrichment for all alerts
- Daily feed sync with Slack notifications

### Meraki Integration
- Firewall log ingestion via syslog
- Security detection rules (C2, cryptomining, database access)
- MITRE ATT&CK mapping
- Real-time alerts to CoPilot

### Graylog Pipelines
- Meraki Security Detection (C2, crypto, DB access, IRC)
- GeoIP Enrichment (location data for all IPs)
- Wazuh JSON parsing (customer labels, rule extraction)

## Customization

### Variables

Edit `ansible/group_vars/all.yml` to customize:
- Network IPs
- Service credentials
- Slack webhook
- Customer information

### Adding New Feeds to MISP

1. SSH to VM2
2. Run: `python3 /opt/siem/misp/scripts/configure-feeds.py`
3. Or use MISP web UI at https://172.16.0.53:8443

### Adding Grafana Dashboards

1. Export dashboard JSON from Grafana
2. Save to `grafana/dashboards/`
3. Redeploy: `./scripts/deploy.sh -t grafana vm3`

## Troubleshooting

### Wazuh Manager daemons restarting
```bash
docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
```

### CoPilot login fails
The auth.py patch is automatically applied. If issues persist:
```bash
docker restart copilot-backend
```

### MISP feeds not syncing
```bash
curl -sk -X POST 'https://localhost:8443/feeds/cacheFeeds/all' \
  -H 'Authorization: DHq00fKEcfBGNerCke9qMvGUHqT83Op5atYwElmM'
```

### Graylog events not appearing in CoPilot
Sync manually:
```bash
/opt/siem/scripts/sync-graylog-to-wazuh.sh
```

## Support

- SOCFortress Discord: https://discord.gg/UN3pNBzaEQ
- CoPilot GitHub: https://github.com/socfortress/CoPilot
- MISP Project: https://www.misp-project.org/
