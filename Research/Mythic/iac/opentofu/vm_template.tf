# VM Template Configuration for Mythic Infrastructure
# Handles Ubuntu 22.04 LTS template cloning and cloud-init provisioning

# Data source to retrieve template VM information
data "proxmox_virtual_environment_vms" "cloud_init_template" {
  node_name = var.proxmox_node
  filter    = "name = '${var.template_name}'"
}

locals {
  # Template VM details
  template_vm = try(
    data.proxmox_virtual_environment_vms.cloud_init_template.virtual_machines[0],
    null
  )

  template_id = local.template_vm != null ? local.template_vm.vm_id : var.template_vmid

  # Cloud-init configuration shared across all VMs
  cloud_init_base = {
    username = var.ssh_user
    ssh_keys = [var.ssh_public_key]

    # Enable cloud-init to run on every boot (required for network reconfiguration)
    run_every_boot = true

    # Disable password auth (SSH keys only)
    disable_password = true
  }
}

# Output template information
output "template_info" {
  value = {
    name  = var.template_name
    vmid  = local.template_id
    ready = local.template_vm != null ? true : false
  }
  description = "Template VM information"
}

# Module for cloud-init configuration
# Generates cloud-init user-data for VMs
locals {
  # Standard packages installed on all VMs
  package_list_base = [
    "curl",
    "wget",
    "htop",
    "net-tools",
    "git",
    "jq",
    "unzip",
    "vim",
    "sudo",
    "openssh-server",
    "openssh-client",
    "ca-certificates",
    "systemd-resolved"  # For DNS
  ]

  # Environment-specific packages
  package_list_mythic = concat(
    local.package_list_base,
    [
      "docker.io",
      "docker-compose",
      "postgresql-client",
      "redis-tools",
      "python3-pip",
      "python3-venv"
    ]
  )

  package_list_redirector = concat(
    local.package_list_base,
    [
      "nginx",
      "socat",
      "dnsmasq",
      "iptables-persistent",
      "conntrack"
    ]
  )

  package_list_monitoring = concat(
    local.package_list_base,
    [
      "curl",
      "wget",
      "prometheus",
      "grafana",
      "node-exporter"
    ]
  )
}

# Cloud-init template generator
# Used by VM modules to create customized user-data
locals {
  cloud_init_template = {
    # Standard network configuration (overridden per VM)
    network_v2 = {
      version = 2
      ethernets = {
        eth0 = {
          dhcp4 = false
          dhcp6 = false
          addresses = []  # Set per VM
          gateway4 = var.gateway_ip
          nameservers = {
            addresses = var.dns_servers
            search    = [var.domain]
          }
        }
      }
    }

    # Packages to install
    packages = local.package_list_base

    # Bootcmd - runs before cloud-init modules
    bootcmd = [
      "echo 'Initializing cloud-init for Mythic infrastructure'",
      "systemctl set-default multi-user.target"
    ]

    # Runcmd - runs after cloud-init modules
    runcmd = [
      "apt-get update",
      "apt-get upgrade -y",
      "systemctl enable ssh"
    ]

    # Disable root login
    disable_root = true

    # Final message
    final_message = "System boot completed at $TIMESTAMP"
  }
}

# Helper function to generate cloud-init YAML for a VM
# Called by vm_mythic.tf, vm_redirector.tf, etc.
locals {
  cloud_init_generators = {
    mythic = {
      packages = local.package_list_mythic
      runcmd = concat(
        local.cloud_init_template.runcmd,
        [
          "groupadd docker || true",
          "usermod -aG docker ${var.ssh_user}",
          "systemctl enable docker",
          "systemctl start docker"
        ]
      )
    }

    redirector = {
      packages = local.package_list_redirector
      runcmd = concat(
        local.cloud_init_template.runcmd,
        [
          "systemctl enable nginx || true",
          "systemctl enable dnsmasq || true",
          "echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf",
          "echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf",
          "sysctl -p"
        ]
      )
    }

    monitoring = {
      packages = local.package_list_monitoring
      runcmd = concat(
        local.cloud_init_template.runcmd,
        [
          "systemctl enable prometheus || true",
          "systemctl enable grafana-server || true",
          "systemctl start prometheus || true",
          "systemctl start grafana-server || true"
        ]
      )
    }

    echidna = {
      packages = local.package_list_base
      runcmd = concat(
        local.cloud_init_template.runcmd,
        [
          "modprobe br_netfilter || true",
          "echo 'net.bridge.bridge-nf-call-iptables = 1' >> /etc/sysctl.conf",
          "sysctl -p"
        ]
      )
    }
  }
}

# Output cloud-init package lists for reference
output "cloud_init_packages" {
  value = {
    base        = local.package_list_base
    mythic      = local.package_list_mythic
    redirector  = local.package_list_redirector
    monitoring  = local.package_list_monitoring
  }
  description = "Package lists for cloud-init provisioning"
}

output "cloud_init_templates" {
  value = {
    mythic      = "See local.cloud_init_generators.mythic"
    redirector  = "See local.cloud_init_generators.redirector"
    monitoring  = "See local.cloud_init_generators.monitoring"
    echidna     = "See local.cloud_init_generators.echidna"
  }
  description = "Cloud-init configuration templates"
}
