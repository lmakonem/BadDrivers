# Monitoring Stack Configuration for Mythic Infrastructure
# Prometheus, Grafana, Loki, and AlertManager
# Only created if enable_monitoring = true

resource "proxmox_virtual_environment_vm" "monitoring" {
  count     = var.enable_monitoring ? 1 : 0
  vmid      = var.monitoring_vmid
  node_name = var.proxmox_node
  name      = "monitoring-01"

  # Clone from template
  clone {
    vm_id = local.template_id
    full  = true
  }

  # Resource allocation
  cpu {
    cores = var.monitoring_cpu_cores
    type  = "host"
  }

  memory {
    dedicated = var.monitoring_memory_mb
    floating  = 0
  }

  # Disk configuration
  disk {
    datastore_id = var.storage_pool
    size         = local.vm_storage_sizes.monitoring
    file_format  = "raw"
    iothread     = true
    cache        = "writethrough"
    discard      = "ignore"
  }

  # Network interface on Mythic VLAN
  network_device {
    bridge   = local.bridge_mythic
    model    = "virtio"
    disabled = false
  }

  # Cloud-init provisioning
  initialization {
    hostname = "monitoring-01"
    dns {
      servers = var.dns_servers
      domain  = var.domain
    }

    user_account {
      username = var.ssh_user
      keys     = [var.ssh_public_key]
    }

    # Static IP
    ip_config {
      ipv4 {
        address = "${var.monitoring_ip}/24"
        gateway = var.gateway_ip
      }
    }

    # Cloud-init user-data
    user_data_base64 = base64encode(
      yamlencode({
        version = 1
        packages = local.cloud_init_generators.monitoring.packages

        package_upgrade = true
        package_reboot_if_required = true

        ssh_deletekeys = false
        ssh_genkeytypes = ["ed25519"]

        # Monitoring-specific configuration
        runcmd = concat(
          local.cloud_init_generators.monitoring.runcmd,
          [
            # Create monitoring directories
            "mkdir -p /var/lib/prometheus",
            "mkdir -p /var/lib/grafana",
            "mkdir -p /var/log/prometheus",
            "mkdir -p /var/log/grafana",
            # Set permissions
            "chown prometheus:prometheus /var/lib/prometheus /var/log/prometheus || true",
            "chown grafana:grafana /var/lib/grafana /var/log/grafana || true",
            # Start services (will be reconfigured by Ansible)
            "systemctl enable prometheus || true",
            "systemctl start prometheus || true",
            "systemctl enable grafana-server || true",
            "systemctl start grafana-server || true"
          ]
        )

        final_message = "Monitoring stack boot completed"
      })
    )
  }

  # CPU limits
  cpu_limit = var.monitoring_cpu_cores
  cpu_sockets = 1

  # Metadata
  description = "Monitoring stack - ${var.environment} environment"
  tags = concat(
    [
      "monitoring",
      "prometheus",
      "grafana",
      "observability"
    ],
    keys(local.common_tags)
  )

  bios = "seabios"

  # Watchdog
  watchdog_device {
    model = "i6300esb"
  }

  # Enable backups
  backup {
    enabled = true
  }

  lifecycle {
    ignore_changes = [
      cloud_init_custom_file,
    ]
  }
}

# Local values for monitoring configuration
locals {
  monitoring_enabled = var.enable_monitoring
  monitoring_fqdn    = "monitoring-01.${var.domain}"

  monitoring_stack = {
    prometheus = {
      port      = 9090
      port_tsdb = 9009
      retention = var.environment == "ops" ? "30d" : "7d"
    }
    grafana = {
      port = 3000
      url  = "http://${var.monitoring_ip}:3000"
    }
    alertmanager = {
      port = 9093
    }
    node_exporter = {
      port = 9100
    }
    loki = {
      port = 3100
    }
  }

  # Data sources for Prometheus scraping
  prometheus_scrape_targets = {
    mythic = {
      job_name = "mythic"
      targets  = var.enable_monitoring ? ["${var.mythic_ip}:9100"] : []
      interval = "15s"
    }
    redirectors = {
      job_name = "redirectors"
      targets  = var.enable_monitoring ? [for ip in local.redirector_ips : "${ip}:9100"] : []
      interval = "15s"
    }
    echidna = {
      job_name = "echidna"
      targets  = var.enable_monitoring ? ["${var.echidna_ip}:9100"] : []
      interval = "15s"
    }
    monitoring = {
      job_name = "prometheus"
      targets  = var.enable_monitoring ? ["127.0.0.1:9090"] : []
      interval = "15s"
    }
    payload = {
      job_name = "payload"
      targets  = var.enable_monitoring && var.enable_payload_servers ? [for ip in local.payload_ips : "${ip}:9100"] : []
      interval = "15s"
    }
  }

  # Alert rules definition
  alerting_rules = {
    instance_down = {
      alert      = "InstanceDown"
      expr       = "up == 0"
      for_period = "5m"
      severity   = "critical"
    }
    high_cpu = {
      alert      = "HighCPU"
      expr       = "process_cpu_seconds_total > 80"
      for_period = "5m"
      severity   = "warning"
    }
    high_memory = {
      alert      = "HighMemory"
      expr       = "process_resident_memory_bytes / 1024 / 1024 > 3000"
      for_period = "5m"
      severity   = "warning"
    }
    disk_full = {
      alert      = "DiskAlmostFull"
      expr       = "(node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.1"
      for_period = "10m"
      severity   = "critical"
    }
  }
}

# Outputs for monitoring configuration
output "monitoring_vm_info" {
  value = var.enable_monitoring ? {
    vm_id    = proxmox_virtual_environment_vm.monitoring[0].id
    vmid     = proxmox_virtual_environment_vm.monitoring[0].vmid
    hostname = proxmox_virtual_environment_vm.monitoring[0].name
    ip       = var.monitoring_ip
    fqdn     = local.monitoring_fqdn
    mac      = try(proxmox_virtual_environment_vm.monitoring[0].network_device[0].mac_address, "unknown")
  } : null
  description = "Monitoring VM identification"
}

output "monitoring_stack_config" {
  value = {
    enabled        = var.enable_monitoring
    prometheus     = local.monitoring_stack.prometheus
    grafana        = local.monitoring_stack.grafana
    alertmanager   = local.monitoring_stack.alertmanager
    node_exporter  = local.monitoring_stack.node_exporter
    loki           = local.monitoring_stack.loki
  }
  description = "Monitoring stack configuration"
}

output "prometheus_scrape_config" {
  value = {
    targets = local.prometheus_scrape_targets
    global = {
      scrape_interval = "15s"
      evaluation_interval = "15s"
      external_labels = {
        environment = var.environment
        cluster     = "mythic-${var.environment}"
      }
    }
  }
  description = "Prometheus scrape configuration"
}

output "alerting_rules_config" {
  value = {
    rules = local.alerting_rules
    alertmanager = {
      port = local.monitoring_stack.alertmanager.port
    }
  }
  description = "Alert rules configuration"
}

# Post-VM creation steps (Ansible will handle):
# 1. Configure Prometheus data retention and scrape intervals
# 2. Deploy Grafana dashboards (Mythic, redirector, system health)
# 3. Configure alert rules and notifications
# 4. Setup Loki for log aggregation
# 5. Configure node_exporter on all VMs
# 6. Setup authentication (Grafana admin credentials)
# 7. Configure data sources and alert channels
# 8. Deploy backup policies for Prometheus data
