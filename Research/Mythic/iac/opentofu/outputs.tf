# OpenTofu Outputs for Mythic Infrastructure
# Provides IP addresses, endpoints, DNS names, and Ansible inventory

# Mythic Server Information
output "mythic_endpoint" {
  value = {
    hostname   = var.mythic_hostname
    fqdn       = "${var.mythic_hostname}.${var.domain}"
    ip         = var.mythic_ip
    api_url    = "https://${var.mythic_hostname}.${var.domain}:7443"
    callbacks  = "https://${var.mythic_hostname}.${var.domain}"
  }
  description = "Mythic server endpoint information"
}

# Redirector Endpoints
output "redirector_endpoints" {
  value = [
    for i in range(var.redirector_count) : {
      name       = "redirector-${i + 1}"
      ip         = local.redirector_ips[i]
      fqdn       = "redirector-${i + 1}.${var.domain}"
      https_url  = "https://redirector-${i + 1}.${var.domain}"
      http_url   = "http://redirector-${i + 1}.${var.domain}"
    }
  ]
  description = "Redirector endpoint URLs"
}

# Payload Server Endpoints (if enabled)
output "payload_endpoints" {
  value = var.enable_payload_servers ? [
    for i in range(var.payload_count) : {
      name      = "payload-${i + 1}"
      ip        = local.payload_ips[i]
      fqdn      = "payload-${i + 1}.${var.domain}"
      https_url = "https://payload-${i + 1}.${var.domain}"
      http_url  = "http://payload-${i + 1}.${var.domain}"
    }
  ] : []
  description = "Payload server endpoint URLs"
}

# Echidna Overlay Endpoint
output "echidna_endpoint" {
  value = {
    hostname   = var.echidna_hostname
    fqdn       = "${var.echidna_hostname}.${var.domain}"
    ip         = var.echidna_ip
    management = "http://${var.echidna_hostname}.${var.domain}:8888"
    telemetry  = "http://${var.echidna_hostname}.${var.domain}:9000"
  }
  description = "Echidna overlay endpoint information"
}

# Monitoring Stack Endpoint
output "monitoring_endpoint" {
  value = var.enable_monitoring ? {
    hostname       = "monitoring-01"
    fqdn           = "monitoring-01.${var.domain}"
    ip             = var.monitoring_ip
    grafana_url    = "http://monitoring-01.${var.domain}:3000"
    prometheus_url = "http://monitoring-01.${var.domain}:9090"
    alertmanager   = "http://monitoring-01.${var.domain}:9093"
  } : null
  description = "Monitoring stack endpoint information"
}

# Comprehensive Ansible Inventory Output
output "ansible_inventory" {
  value = {
    mythic_servers = {
      hosts = {
        (var.mythic_hostname) = {
          ansible_host = var.mythic_ip
          ansible_user = var.ssh_user
          role         = "mythic"
          vmid         = var.mythic_vmid
        }
      }
      vars = {
        domain = var.domain
        environment = var.environment
      }
    }
    redirectors = {
      hosts = {
        for i in range(var.redirector_count) :
        "redirector-${i + 1}" => {
          ansible_host = local.redirector_ips[i]
          ansible_user = var.ssh_user
          role         = "redirector"
          vmid         = var.redirector_vmid_base + i
        }
      }
      vars = {
        domain = var.domain
        environment = var.environment
      }
    }
    echidna = {
      hosts = {
        (var.echidna_hostname) = {
          ansible_host = var.echidna_ip
          ansible_user = var.ssh_user
          role         = "echidna"
          vmid         = var.echidna_vmid
        }
      }
      vars = {
        domain = var.domain
        environment = var.environment
      }
    }
    monitoring = var.enable_monitoring ? {
      hosts = {
        "monitoring-01" = {
          ansible_host = var.monitoring_ip
          ansible_user = var.ssh_user
          role         = "monitoring"
          vmid         = var.monitoring_vmid
        }
      }
      vars = {
        domain = var.domain
        environment = var.environment
      }
    } : {
      hosts = {}
      vars = {
        domain = var.domain
        environment = var.environment
      }
    }
    payload = var.enable_payload_servers ? {
      hosts = {
        for i in range(var.payload_count) :
        "payload-${i + 1}" => {
          ansible_host = local.payload_ips[i]
          ansible_user = var.ssh_user
          role         = "payload"
          vmid         = var.payload_vmid_base + i
        }
      }
      vars = {
        domain = var.domain
        environment = var.environment
      }
    } : {
      hosts = {}
      vars = {
        domain = var.domain
        environment = var.environment
      }
    }
  }
  description = "Ansible inventory in YAML-compatible format"
}

# Network Configuration Summary
output "network_summary" {
  value = {
    mythic_vlan = {
      vlan_tag = var.bridge_vlan_mythic
      gateway  = var.gateway_ip
      bridge   = local.bridge_mythic
    }
    agent_vlan = {
      vlan_tag = var.bridge_vlan_agents
      gateway  = "192.168.10.1"
      bridge   = local.bridge_agents
    }
    dns_servers = var.dns_servers
    domain      = var.domain
  }
  description = "Network configuration overview"
}

# VM IP Address Mapping
output "vm_ip_map" {
  value = {
    mythic      = var.mythic_ip
    redirectors = {
      for i in range(var.redirector_count) :
      "redirector-${i + 1}" => local.redirector_ips[i]
    }
    echidna     = var.echidna_ip
    monitoring  = var.enable_monitoring ? var.monitoring_ip : null
    payload     = var.enable_payload_servers ? {
      for i in range(var.payload_count) :
      "payload-${i + 1}" => local.payload_ips[i]
    } : {}
  }
  description = "All VM IP addresses"
}

# DNS Entries (for reference)
output "dns_entries" {
  value = {
    mythic = "${var.mythic_hostname}.${var.domain} A ${var.mythic_ip}"
    redirectors = [
      for i in range(var.redirector_count) :
      "redirector-${i + 1}.${var.domain} A ${local.redirector_ips[i]}"
    ]
    echidna = "${var.echidna_hostname}.${var.domain} A ${var.echidna_ip}"
    monitoring = var.enable_monitoring ? "monitoring-01.${var.domain} A ${var.monitoring_ip}" : null
    payload = var.enable_payload_servers ? [
      for i in range(var.payload_count) :
      "payload-${i + 1}.${var.domain} A ${local.payload_ips[i]}"
    ] : []
  }
  description = "DNS A records for all VMs"
}

# Deployment Summary
output "deployment_summary" {
  value = {
    environment    = var.environment
    total_vms      = (var.redirector_count + 3 +
                      (var.enable_monitoring ? 1 : 0) +
                      (var.enable_payload_servers ? var.payload_count : 0))
    total_cpu      = (var.mythic_cpu_cores +
                      (var.redirector_cpu_cores * var.redirector_count) +
                      var.echidna_cpu_cores +
                      (var.enable_monitoring ? var.monitoring_cpu_cores : 0) +
                      (var.enable_payload_servers ? var.payload_cpu_cores * var.payload_count : 0))
    total_memory_mb = (var.mythic_memory_mb +
                       (var.redirector_memory_mb * var.redirector_count) +
                       var.echidna_memory_mb +
                       (var.enable_monitoring ? var.monitoring_memory_mb : 0) +
                       (var.enable_payload_servers ? var.payload_memory_mb * var.payload_count : 0))
    total_storage_gb = (local.vm_storage_sizes.mythic +
                        (local.vm_storage_sizes.redirector * var.redirector_count) +
                        local.vm_storage_sizes.echidna +
                        (var.enable_monitoring ? local.vm_storage_sizes.monitoring : 0) +
                        (var.enable_payload_servers ? local.vm_storage_sizes.payload * var.payload_count : 0))
    proxmox_node   = var.proxmox_node
    storage_pool   = var.storage_pool
  }
  description = "Deployment resource summary"
}

# Quick Reference
output "quick_reference" {
  value = {
    access_mythic_api = "https://${var.mythic_hostname}.${var.domain}:7443"
    access_grafana    = var.enable_monitoring ? "http://monitoring-01.${var.domain}:3000" : "N/A"
    ssh_to_mythic     = "ssh ${var.ssh_user}@${var.mythic_ip}"
    ssh_to_redirector_1 = "ssh ${var.ssh_user}@${local.redirector_ips[0]}"
    ansible_command   = "ansible-inventory -i inventory/lab.yml --graph"
  }
  description = "Quick reference for common operations"
}
