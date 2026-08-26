# Network Configuration for Mythic Infrastructure
# Defines VLANs, bridges, and routing for lab environment
# VLAN 20: Mythic infrastructure (redirectors, Mythic server, Echidna)
# VLAN 10: Agent targets (emulated victim machines)

# Note: Proxmox network interfaces are typically managed outside Terraform.
# This file documents the expected configuration and provides reference outputs.
# Manual setup on Proxmox node:
#   - Bridge: vmbr0 (untagged, for VM management)
#   - VLAN 20: vmbr20 (Mythic infrastructure)
#   - VLAN 10: vmbr10 (agent targets)
#   - Trunk ports configured with these VLANs

# Reference: Expected VLAN Configuration (Proxmox /etc/network/interfaces)
# auto vmbr20
# iface vmbr20 inet static
#     address 192.168.20.1/24
#     bridge-ports eno1.20
#     bridge-stp off
#     bridge-fd 0
#
# auto vmbr10
# iface vmbr10 inet static
#     address 192.168.10.1/24
#     bridge-ports eno1.10
#     bridge-stp off
#     bridge-fd 0

# Network Configuration Local Values
locals {
  # Mythic infrastructure VLAN
  vlan_mythic = var.bridge_vlan_mythic
  bridge_mythic = "vmbr${var.bridge_vlan_mythic}"

  # Agent targets VLAN
  vlan_agents = var.bridge_vlan_agents
  bridge_agents = "vmbr${var.bridge_vlan_agents}"

  # Gateway for Mythic VLAN
  gateway = var.gateway_ip
  dns_list = var.dns_servers

  # Domain configuration
  domain_mythic = "mythic.${var.domain}"
}

# Reference DNS configuration for cloud-init
# Used by vm_mythic.tf and other VM modules
locals {
  dns_config = {
    nameservers = local.dns_list
    search      = [var.domain, local.domain_mythic]
    options = [
      "timeout:2",
      "attempts:2"
    ]
  }
}

# IP address calculation for redirectors
# Generates sequential IPs from the base IP
locals {
  redirector_ips = [
    for i in range(var.redirector_count) :
    join(".", [
      local.redirector_ip_octets[0],
      local.redirector_ip_octets[1],
      local.redirector_ip_octets[2],
      tostring(local.redirector_base_num + i)
    ])
  ]
}

# IP address calculation for payload servers
locals {
  payload_ips = [
    for i in range(var.payload_count) :
    join(".", [
      local.payload_ip_octets[0],
      local.payload_ip_octets[1],
      local.payload_ip_octets[2],
      tostring(local.payload_base_num + i)
    ])
  ]
}

# Network outputs for Ansible inventory generation
output "network_config" {
  value = {
    vlan_mythic      = local.vlan_mythic
    vlan_agents      = local.vlan_agents
    bridge_mythic    = local.bridge_mythic
    bridge_agents    = local.bridge_agents
    gateway          = local.gateway
    dns_servers      = local.dns_list
    domain           = var.domain
    domain_mythic    = local.domain_mythic
  }
  description = "Network configuration summary for Ansible"
}

output "mythic_vlan_config" {
  value = {
    vlan_tag = local.vlan_mythic
    gateway  = local.gateway
    bridge   = local.bridge_mythic
    dns      = local.dns_list
  }
  description = "Mythic VLAN configuration details"
}

output "agent_vlan_config" {
  value = {
    vlan_tag = local.vlan_agents
    gateway  = "192.168.10.1"  # Typically x.10.1
    bridge   = local.bridge_agents
  }
  description = "Agent target VLAN configuration"
}

output "redirector_ip_map" {
  value = {
    for i, ip in local.redirector_ips :
    "redirector-${i + 1}" => {
      ip = ip
      hostname = "redirector-${i + 1}.${var.domain}"
    }
  }
  description = "Redirector IP address mapping"
}

output "payload_server_ips" {
  value       = var.enable_payload_servers ? local.payload_ips : []
  description = "Payload server IP addresses"
}
