# Mythic Server VM Configuration
# Main C2 server with database, broker, and container orchestration
# 8 GB RAM, 4 CPU cores, 50 GB disk

resource "proxmox_virtual_environment_vm" "mythic" {
  vmid      = var.mythic_vmid
  node_name = var.proxmox_node
  name      = var.mythic_hostname

  # Clone from template
  clone {
    vm_id = local.template_id
    full  = true  # Full clone, not linked
  }

  # Resource allocation
  cpu {
    cores = var.mythic_cpu_cores
    type  = "host"  # Use host CPU (for lab)
  }

  memory {
    dedicated = var.mythic_memory_mb
    floating  = 0
  }

  # Disk configuration
  disk {
    datastore_id = var.storage_pool
    size         = local.vm_storage_sizes.mythic
    file_format  = "raw"
    iothread     = true  # Enable I/O threading for performance
    cache        = "writethrough"
    discard      = "ignore"
  }

  # Network interface on Mythic VLAN (20)
  network_device {
    bridge   = local.bridge_mythic
    model    = "virtio"
    disabled = false
  }

  # Cloud-init provisioning
  initialization {
    # DNS and hostname
    hostname = var.mythic_hostname
    dns {
      servers = var.dns_servers
      domain  = var.domain
    }

    # User and SSH keys
    user_account {
      username = var.ssh_user
      keys     = [var.ssh_public_key]
      password = "temporary"  # Ignored if SSH keys configured
    }

    # Network configuration (static IP)
    ip_config {
      ipv4 {
        address = "${var.mythic_ip}/24"
        gateway = var.gateway_ip
      }
    }

    # Custom cloud-init user-data for Mythic-specific setup
    user_data_base64 = base64encode(
      yamlencode({
        version = 1
        packages = local.cloud_init_generators.mythic.packages

        # System updates
        package_upgrade = true
        package_reboot_if_required = true

        # SSH hardening
        ssh_deletekeys = false
        ssh_genkeytypes = ["ed25519"]

        # Run commands
        runcmd = concat(
          local.cloud_init_generators.mythic.runcmd,
          [
            "echo '${var.mythic_hostname} all Privileged commands require authentication' | tee /etc/sudoers.d/mythic-sudo",
            "chmod 0440 /etc/sudoers.d/mythic-sudo"
          ]
        )

        # Final message
        final_message = "Mythic server boot completed at $TIMESTAMP"
      })
    )
  }

  # Resource limits
  cpu_limit = var.mythic_cpu_cores
  cpu_sockets = 1

  # VM metadata
  description = "Mythic C2 server - ${var.environment} environment"
  tags        = concat(
    [
      "mythic",
      "database",
      "broker",
      "c2-server"
    ],
    keys(local.common_tags)
  )

  # Boot settings
  bios = "seabios"  # Standard BIOS for compatibility

  # Watchdog for automatic restart on kernel panic
  watchdog_device {
    model = "i6300esb"
  }

  # Enable backups
  backup {
    enabled = true
  }

  # Lifecycle management
  lifecycle {
    ignore_changes = [
      cloud_init_custom_file,  # Ignore cloud-init changes after first boot
    ]
  }
}

# Local values for Mythic-specific configuration
locals {
  mythic_fqdn = "${var.mythic_hostname}.${var.domain}"
  mythic_container_ports = {
    api             = 7443
    callback_https  = 443
    callback_http   = 80
    monitoring      = 8888
    database        = 5432
    broker          = 6379
  }
}

# Outputs for Ansible and other consumers
output "mythic_vm_info" {
  value = {
    vm_id    = proxmox_virtual_environment_vm.mythic.id
    vmid     = proxmox_virtual_environment_vm.mythic.vmid
    hostname = proxmox_virtual_environment_vm.mythic.name
    ip       = var.mythic_ip
    fqdn     = local.mythic_fqdn
    mac      = try(proxmox_virtual_environment_vm.mythic.network_device[0].mac_address, "unknown")
  }
  description = "Mythic VM identification and network details"
}

output "mythic_container_ports" {
  value = {
    api             = local.mythic_container_ports.api
    callback_https  = local.mythic_container_ports.callback_https
    callback_http   = local.mythic_container_ports.callback_http
    monitoring      = local.mythic_container_ports.monitoring
    database        = local.mythic_container_ports.database
    broker          = local.mythic_container_ports.broker
  }
  description = "Mythic container port mapping"
}

output "mythic_ansible_host" {
  value = {
    hostname = var.mythic_hostname
    ip       = var.mythic_ip
    user     = var.ssh_user
    port     = 22
  }
  description = "Mythic VM details for Ansible inventory"
}

# Planned post-VM creation steps (handled by Ansible):
# 1. Install Docker daemon + Docker Compose
# 2. Clone Mythic repository
# 3. Configure environment variables (.env file)
# 4. Build and start Mythic containers:
#    - mythic_db (PostgreSQL)
#    - mythic_broker (Redis)
#    - mythic_http (Mythic API server)
# 5. Configure TLS certificates
# 6. Deploy initial C2 profiles
# 7. Configure monitoring agents
# 8. Harden SSH, firewall, and system services
