# Echidna Overlay VM Configuration
# Handles inter-zone traffic, payload decoration, and infrastructure telemetry
# 2 CPU cores, 4 GB RAM, 30 GB disk

resource "proxmox_virtual_environment_vm" "echidna" {
  vmid      = var.echidna_vmid
  node_name = var.proxmox_node
  name      = var.echidna_hostname

  # Clone from template
  clone {
    vm_id = local.template_id
    full  = true
  }

  # Resource allocation
  cpu {
    cores = var.echidna_cpu_cores
    type  = "host"
  }

  memory {
    dedicated = var.echidna_memory_mb
    floating  = 0
  }

  # Disk configuration
  disk {
    datastore_id = var.storage_pool
    size         = local.vm_storage_sizes.echidna
    file_format  = "raw"
    iothread     = true
    cache        = "writethrough"
    discard      = "ignore"
  }

  # Primary network interface on Mythic VLAN (20)
  network_device {
    bridge   = local.bridge_mythic
    model    = "virtio"
    disabled = false
  }

  # Secondary network interface on agent VLAN (10) - for traffic interception
  network_device {
    bridge   = local.bridge_agents
    model    = "virtio"
    disabled = false
  }

  # Cloud-init provisioning
  initialization {
    hostname = var.echidna_hostname
    dns {
      servers = var.dns_servers
      domain  = var.domain
    }

    user_account {
      username = var.ssh_user
      keys     = [var.ssh_public_key]
    }

    # Network configuration - dual interfaces
    # Note: This may need adjustment depending on cloud-init version
    ip_config {
      ipv4 {
        address = "${var.echidna_ip}/24"
        gateway = var.gateway_ip
      }
    }

    # Cloud-init user-data for Echidna
    user_data_base64 = base64encode(
      yamlencode({
        version = 1
        packages = concat(
          local.package_list_base,
          [
            "bridge-utils",
            "vlan",
            "iptables-persistent",
            "conntrack",
            "tcpdump",
            "netcat-openbsd",
            "socat",
            "python3-pip",
            "python3-dev",
            "libnetfilter-queue-dev"
          ]
        )

        package_upgrade = true
        package_reboot_if_required = true

        ssh_deletekeys = false
        ssh_genkeytypes = ["ed25519"]

        # Echidna-specific configuration
        runcmd = concat(
          local.cloud_init_template.runcmd,
          [
            # Enable IP forwarding and bridging
            "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.conf",
            "echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf",
            "echo 'net.ipv4.conf.all.rp_filter = 0' >> /etc/sysctl.conf",
            "echo 'net.ipv4.conf.default.rp_filter = 0' >> /etc/sysctl.conf",
            # Enable bridge netfilter
            "echo 'net.bridge.bridge-nf-call-iptables = 1' >> /etc/sysctl.conf",
            "echo 'net.bridge.bridge-nf-call-arptables = 1' >> /etc/sysctl.conf",
            "sysctl -p",
            # Load required kernel modules
            "modprobe br_netfilter || true",
            "modprobe nf_conntrack || true",
            "modprobe nfnetlink_queue || true",
            # Create Echidna user and group
            "useradd -r -s /bin/bash echidna || true",
            "mkdir -p /var/log/echidna",
            "chown echidna:echidna /var/log/echidna"
          ]
        )

        final_message = "Echidna overlay boot completed"
      })
    )
  }

  # CPU limits
  cpu_limit = var.echidna_cpu_cores
  cpu_sockets = 1

  # Metadata
  description = "Echidna overlay VM - ${var.environment} environment"
  tags = concat(
    [
      "echidna",
      "overlay",
      "interceptor",
      "telemetry"
    ],
    keys(local.common_tags)
  )

  bios = "seabios"

  # Watchdog for stability
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

  # Depends on network configuration
  depends_on = []
}

# Local values for Echidna configuration
locals {
  echidna_fqdn = "${var.echidna_hostname}.${var.domain}"

  echidna_ports = {
    management = 8888
    telemetry  = 9000
  }

  # Interface mapping
  echidna_interfaces = {
    mythic_vlan = {
      vlan_id = var.bridge_vlan_mythic
      gateway = var.gateway_ip
      ip      = var.echidna_ip
    }
    agent_vlan = {
      vlan_id = var.bridge_vlan_agents
      gateway = "192.168.10.1"
      ip      = "192.168.10.40"  # Secondary IP on agent VLAN
    }
  }
}

# Outputs for Echidna
output "echidna_vm_info" {
  value = {
    vm_id    = proxmox_virtual_environment_vm.echidna.id
    vmid     = proxmox_virtual_environment_vm.echidna.vmid
    hostname = proxmox_virtual_environment_vm.echidna.name
    ip       = var.echidna_ip
    fqdn     = local.echidna_fqdn
    mac_primary   = try(proxmox_virtual_environment_vm.echidna.network_device[0].mac_address, "unknown")
    mac_secondary = try(proxmox_virtual_environment_vm.echidna.network_device[1].mac_address, "unknown")
  }
  description = "Echidna VM identification and network details"
}

output "echidna_network_config" {
  value = {
    mythic_interface = local.echidna_interfaces.mythic_vlan
    agent_interface  = local.echidna_interfaces.agent_vlan
  }
  description = "Echidna network interface configuration"
}

output "echidna_ports" {
  value = {
    management = local.echidna_ports.management
    telemetry  = local.echidna_ports.telemetry
  }
  description = "Echidna service ports"
}

# Post-VM creation steps (Ansible will handle):
# 1. Install and configure Echidna C2 implant overlay
# 2. Configure network bridging and VLAN trunking
# 3. Setup netfilter queues for traffic interception
# 4. Configure payload decoration logic
# 5. Setup telemetry collection and reporting
# 6. Configure logging and monitoring
# 7. Security hardening (SELinux, AppArmor)
# 8. Network isolation and traffic filtering
