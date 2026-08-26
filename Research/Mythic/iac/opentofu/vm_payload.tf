# Payload Staging Server VM Configuration (Optional)
# For hosting generated payloads and artifacts
# 2 GB RAM, 2 CPU cores, 30 GB disk
# Only created if enable_payload_servers = true

resource "proxmox_virtual_environment_vm" "payload" {
  for_each = var.enable_payload_servers ? toset([for i in range(var.payload_count) : tostring(i)]) : toset([])

  vmid      = var.payload_vmid_base + tonumber(each.key)
  node_name = var.proxmox_node
  name      = "payload-${tonumber(each.key) + 1}"

  # Clone from template
  clone {
    vm_id = local.template_id
    full  = true
  }

  # Resource allocation
  cpu {
    cores = var.payload_cpu_cores
    type  = "host"
  }

  memory {
    dedicated = var.payload_memory_mb
    floating  = 0
  }

  # Disk configuration
  disk {
    datastore_id = var.storage_pool
    size         = local.vm_storage_sizes.payload
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
    hostname = "payload-${tonumber(each.key) + 1}"
    dns {
      servers = var.dns_servers
      domain  = var.domain
    }

    user_account {
      username = var.ssh_user
      keys     = [var.ssh_public_key]
    }

    # Static IP from calculated list
    ip_config {
      ipv4 {
        address = "${local.payload_ips[tonumber(each.key)]}/24"
        gateway = var.gateway_ip
      }
    }

    # Cloud-init user-data for payload servers
    user_data_base64 = base64encode(
      yamlencode({
        version = 1
        packages = concat(
          local.package_list_base,
          [
            "nginx",
            "curl",
            "wget",
            "python3-http.server"
          ]
        )

        package_upgrade = true
        package_reboot_if_required = true

        ssh_deletekeys = false
        ssh_genkeytypes = ["ed25519"]

        # Payload-specific configuration
        runcmd = concat(
          local.cloud_init_template.runcmd,
          [
            # Create payload directory
            "mkdir -p /opt/payloads",
            "chown ${var.ssh_user}:${var.ssh_user} /opt/payloads",
            "chmod 755 /opt/payloads",
            # Start nginx for HTTP payload serving
            "systemctl enable nginx",
            "systemctl start nginx || true",
            # Log completion
            "echo 'Payload server ready at http://payload-${tonumber(each.key) + 1}.${var.domain}:80' > /var/log/payload-init.log"
          ]
        )

        final_message = "Payload server boot completed"
      })
    )
  }

  # CPU limits
  cpu_limit = var.payload_cpu_cores
  cpu_sockets = 1

  # Metadata
  description = "Mythic payload server-${tonumber(each.key) + 1} - ${var.environment}"
  tags = concat(
    [
      "payload",
      "file-hosting",
      "artifact-server"
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

# Local values for payload configuration
locals {
  payload_hostnames = var.enable_payload_servers ? [
    for i in range(var.payload_count) :
    "payload-${i + 1}.${var.domain}"
  ] : []

  payload_ports = {
    http = 80
    https = 443
  }
}

# Output payload server information
output "payload_vm_info" {
  value = var.enable_payload_servers ? {
    for i in range(var.payload_count) :
    "payload-${i + 1}" => {
      vm_id    = proxmox_virtual_environment_vm.payload[tostring(i)].id
      vmid     = proxmox_virtual_environment_vm.payload[tostring(i)].vmid
      hostname = "payload-${i + 1}"
      ip       = local.payload_ips[i]
      fqdn     = "payload-${i + 1}.${var.domain}"
      mac      = try(proxmox_virtual_environment_vm.payload[tostring(i)].network_device[0].mac_address, "unknown")
    }
  } : {}
  description = "Payload server VM details"
}

output "payload_servers_enabled" {
  value       = var.enable_payload_servers
  description = "Whether payload servers are enabled"
}

output "payload_inventory" {
  value = {
    enabled   = var.enable_payload_servers
    hostnames = local.payload_hostnames
    ips       = var.enable_payload_servers ? local.payload_ips : []
    count     = var.payload_count
  }
  description = "Payload server inventory for Ansible"
}

# Post-VM creation steps (Ansible will handle):
# 1. Configure nginx for HTTPS payload delivery
# 2. Setup /opt/payloads directory with proper permissions
# 3. Configure download rate limiting
# 4. Setup logging and monitoring
# 5. Configure TLS certificates
# 6. Deploy payload organization scripts
