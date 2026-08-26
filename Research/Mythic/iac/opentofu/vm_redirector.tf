# Redirector VM Configuration
# Stateless redirector servers for nginx/socat/dnsmasq
# 2 GB RAM, 2 CPU cores, 20 GB disk
# Creates var.redirector_count instances

resource "proxmox_virtual_environment_vm" "redirector" {
  for_each = toset([for i in range(var.redirector_count) : tostring(i)])

  vmid      = var.redirector_vmid_base + tonumber(each.key)
  node_name = var.proxmox_node
  name      = "redirector-${tonumber(each.key) + 1}"

  # Clone from template
  clone {
    vm_id = local.template_id
    full  = true
  }

  # Resource allocation (smaller than Mythic)
  cpu {
    cores = var.redirector_cpu_cores
    type  = "host"
  }

  memory {
    dedicated = var.redirector_memory_mb
    floating  = 0
  }

  # Disk configuration (smaller, stateless)
  disk {
    datastore_id = var.storage_pool
    size         = local.vm_storage_sizes.redirector
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
    hostname = "redirector-${tonumber(each.key) + 1}"
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
        address = "${local.redirector_ips[tonumber(each.key)]}/24"
        gateway = var.gateway_ip
      }
    }

    # Cloud-init user-data
    user_data_base64 = base64encode(
      yamlencode({
        version = 1
        packages = local.cloud_init_generators.redirector.packages

        package_upgrade = true
        package_reboot_if_required = true

        ssh_deletekeys = false
        ssh_genkeytypes = ["ed25519"]

        # Redirector-specific configuration
        runcmd = concat(
          local.cloud_init_generators.redirector.runcmd,
          [
            # Enable IP forwarding and routing
            "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.conf",
            "echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf",
            "echo 'net.ipv4.conf.default.rp_filter = 0' >> /etc/sysctl.conf",
            "sysctl -p",
            # Disable UFW by default (hardening.yml will configure it)
            "systemctl disable ufw || true",
            # Start nginx (will be configured by Ansible)
            "systemctl enable nginx",
            "systemctl start nginx || true"
          ]
        )

        final_message = "Redirector-${tonumber(each.key) + 1} boot completed"
      })
    )
  }

  # CPU limits
  cpu_limit = var.redirector_cpu_cores
  cpu_sockets = 1

  # Metadata
  description = "Mythic redirector-${tonumber(each.key) + 1} - ${var.environment}"
  tags = concat(
    [
      "redirector",
      "nginx",
      "socat",
      "dnsmasq"
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

  # Ensure Mythic server exists before creating redirectors
  # (optional, only if using physical traffic flows)
  # depends_on = [proxmox_virtual_environment_vm.mythic]
}

# Local values for redirector configuration
locals {
  redirector_hostnames = [
    for i in range(var.redirector_count) :
    "redirector-${i + 1}.${var.domain}"
  ]

  redirector_ports = {
    http  = 80
    https = 443
    dns   = 53
    socat_traffic = 5000  # Custom traffic relay
  }
}

# Map of redirector IPs to hostnames
output "redirector_vm_info" {
  value = {
    for i in range(var.redirector_count) :
    "redirector-${i + 1}" => {
      vm_id    = proxmox_virtual_environment_vm.redirector[tostring(i)].id
      vmid     = proxmox_virtual_environment_vm.redirector[tostring(i)].vmid
      hostname = "redirector-${i + 1}"
      ip       = local.redirector_ips[i]
      fqdn     = "redirector-${i + 1}.${var.domain}"
      mac      = try(proxmox_virtual_environment_vm.redirector[tostring(i)].network_device[0].mac_address, "unknown")
    }
  }
  description = "Redirector VM details for all instances"
}

output "redirector_inventory" {
  value = {
    hostnames = local.redirector_hostnames
    ips       = local.redirector_ips
    count     = var.redirector_count
  }
  description = "Redirector inventory for Ansible"
}

output "redirector_ports" {
  value = {
    http           = local.redirector_ports.http
    https          = local.redirector_ports.https
    dns            = local.redirector_ports.dns
    socat_traffic  = local.redirector_ports.socat_traffic
  }
  description = "Redirector service ports"
}

# Post-VM creation steps (Ansible will handle):
# 1. Configure nginx reverse proxy:
#    - HTTPS termination with TLS certs
#    - Proxy traffic to Mythic callbacks
#    - Rate limiting and WAF rules
# 2. Configure socat for low-level traffic relay
# 3. Configure dnsmasq for DNS sinkhole/redirection
# 4. Setup iptables for traffic manipulation
# 5. Configure monitoring agents
# 6. Harden firewall and system settings
