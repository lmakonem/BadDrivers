# Firewall Configuration for Mythic Infrastructure
# Defines UFW rules per VM role (Mythic, redirector, Echidna, monitoring)
# These rules are delivered via Ansible playbooks/1-hardening.yml

locals {
  # SSH ingress from admin networks
  ssh_ingress_sources = var.ingress_whitelist

  # Firewall rules per VM role
  firewall_rules = {
    mythic = {
      description = "Mythic C2 server firewall rules"
      ingress = [
        {
          port     = 22
          protocol = "tcp"
          comment  = "SSH admin access"
          sources  = local.ssh_ingress_sources
        },
        {
          port     = 7443
          protocol = "tcp"
          comment  = "Mythic API HTTPS (internal)"
          sources  = ["192.168.20.0/24"]
        },
        {
          port     = 443
          protocol = "tcp"
          comment  = "HTTPS callbacks"
          sources  = ["0.0.0.0/0"]  # From redirectors and external
        },
        {
          port     = 80
          protocol = "tcp"
          comment  = "HTTP callbacks (if configured)"
          sources  = ["0.0.0.0/0"]
        },
        {
          port     = 5432
          protocol = "tcp"
          comment  = "PostgreSQL (local only)"
          sources  = ["192.168.20.0/24"]
        },
        {
          port     = 6379
          protocol = "tcp"
          comment  = "Redis broker (local only)"
          sources  = ["192.168.20.0/24"]
        }
      ]
      egress = [
        {
          port     = 0
          protocol = "all"
          comment  = "Allow all outbound (restrict per policy)"
          sources  = ["0.0.0.0/0"]
        }
      ]
    }

    redirector = {
      description = "Redirector firewall rules"
      ingress = [
        {
          port     = 22
          protocol = "tcp"
          comment  = "SSH admin access"
          sources  = local.ssh_ingress_sources
        },
        {
          port     = 443
          protocol = "tcp"
          comment  = "HTTPS (nginx reverse proxy)"
          sources  = ["0.0.0.0/0"]
        },
        {
          port     = 80
          protocol = "tcp"
          comment  = "HTTP (nginx reverse proxy)"
          sources  = ["0.0.0.0/0"]
        },
        {
          port     = 53
          protocol = "tcp"
          comment  = "DNS (dnsmasq)"
          sources  = ["192.168.10.0/24", "192.168.20.0/24"]
        },
        {
          port     = 53
          protocol = "udp"
          comment  = "DNS UDP (dnsmasq)"
          sources  = ["192.168.10.0/24", "192.168.20.0/24"]
        },
        {
          port     = 5000
          protocol = "tcp"
          comment  = "socat traffic relay (custom)"
          sources  = ["192.168.10.0/24"]
        }
      ]
      egress = [
        {
          port     = 0
          protocol = "all"
          comment  = "Allow all outbound"
          sources  = ["0.0.0.0/0"]
        }
      ]
    }

    echidna = {
      description = "Echidna overlay firewall rules"
      ingress = [
        {
          port     = 22
          protocol = "tcp"
          comment  = "SSH admin access"
          sources  = local.ssh_ingress_sources
        },
        {
          port     = 8888
          protocol = "tcp"
          comment  = "Echidna management interface"
          sources  = ["192.168.20.0/24"]
        },
        {
          port     = 9000
          protocol = "tcp"
          comment  = "Echidna telemetry collection"
          sources  = ["192.168.10.0/24", "192.168.20.0/24"]
        }
      ]
      egress = [
        {
          port     = 0
          protocol = "all"
          comment  = "Allow all outbound"
          sources  = ["0.0.0.0/0"]
        }
      ]
    }

    monitoring = {
      description = "Monitoring stack firewall rules"
      ingress = [
        {
          port     = 22
          protocol = "tcp"
          comment  = "SSH admin access"
          sources  = local.ssh_ingress_sources
        },
        {
          port     = 3000
          protocol = "tcp"
          comment  = "Grafana dashboard"
          sources  = ["192.168.20.0/24"]
        },
        {
          port     = 9090
          protocol = "tcp"
          comment  = "Prometheus API"
          sources  = ["192.168.20.0/24"]
        },
        {
          port     = 9100
          protocol = "tcp"
          comment  = "Node exporter metrics"
          sources  = ["192.168.20.0/24"]
        },
        {
          port     = 9093
          protocol = "tcp"
          comment  = "Alertmanager"
          sources  = ["192.168.20.0/24"]
        }
      ]
      egress = [
        {
          port     = 0
          protocol = "all"
          comment  = "Allow all outbound"
          sources  = ["0.0.0.0/0"]
        }
      ]
    }

    payload = {
      description = "Payload server firewall rules"
      ingress = [
        {
          port     = 22
          protocol = "tcp"
          comment  = "SSH admin access"
          sources  = local.ssh_ingress_sources
        },
        {
          port     = 443
          protocol = "tcp"
          comment  = "HTTPS payload delivery"
          sources  = ["0.0.0.0/0"]
        },
        {
          port     = 80
          protocol = "tcp"
          comment  = "HTTP payload delivery"
          sources  = ["0.0.0.0/0"]
        }
      ]
      egress = [
        {
          port     = 0
          protocol = "all"
          comment  = "Allow all outbound"
          sources  = ["0.0.0.0/0"]
        }
      ]
    }
  }
}

# Output firewall rules for Ansible
output "firewall_rules_by_role" {
  value = {
    mythic      = local.firewall_rules.mythic
    redirector  = local.firewall_rules.redirector
    echidna     = local.firewall_rules.echidna
    monitoring  = local.firewall_rules.monitoring
    payload     = local.firewall_rules.payload
  }
  description = "Firewall rules organized by VM role"
}

# Generate Ansible-compatible firewall configuration
output "ufw_rules_json" {
  value = {
    deny_incoming = "yes"
    default_incoming = "deny"
    default_outgoing = "allow"
    enable = var.enable_ufw
  }
  description = "UFW default policy configuration"
}

# Documentation: Firewall implementation
# Implement in: ansible/roles/hardening/tasks/main.yml
# Example UFW rule:
#   - name: Allow SSH from admin networks
#     ufw:
#       rule: allow
#       port: "22"
#       proto: tcp
#       from_ip: "{{ item }}"
#     loop: "{{ ingress_whitelist }}"
#
# Additional security considerations:
# 1. fail2ban for SSH brute-force protection
# 2. Rate limiting on public endpoints
# 3. Connection tracking (conntrack) limits
# 4. ICMP rate limiting
# 5. SYN flood protection
# 6. UDP flood protection
# 7. Port scan detection

locals {
  additional_security_rules = {
    fail2ban = {
      enabled      = true
      ssh_maxretry = 3
      ssh_findtime = 3600
      ssh_bantime  = 86400
    }
    conntrack = {
      max_connections = 100000
      timeout_established = 432000  # 5 days
      timeout_time_wait = 120
    }
    icmp = {
      rate_limit = "100/second"
    }
  }
}

output "additional_security_config" {
  value = local.additional_security_rules
  description = "Additional security hardening configuration"
}
