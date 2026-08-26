# OpenTofu Main Configuration for Mythic C2 Infrastructure
# Provider: proxmox-ve
# State: Stored in Proxmox or local (configure in terraform.tf)

terraform {
  required_version = ">= 1.0"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.45.0"
    }
  }
  # Uncomment for remote state backend (requires Vault or S3)
  # backend "http" {
  #   address        = "https://vault.mythic.lab/v1/mythic/tfstate/lab"
  #   lock_address   = "https://vault.mythic.lab/v1/mythic/tfstate/lab/lock"
  #   unlock_address = "https://vault.mythic.lab/v1/mythic/tfstate/lab/lock"
  #   username       = "terraform"
  # }
}

# Proxmox Provider Configuration
provider "proxmox" {
  # API endpoint: https://proxmox-ip:8006
  endpoint = var.proxmox_host
  username = var.proxmox_username
  password = var.proxmox_password
  insecure = true  # Lab environment - disable in production
}

# Local values for dynamic IP calculation
locals {
  environment = var.environment

  # Parse redirector base IP to generate individual IPs
  redirector_ip_octets = split(".", var.redirector_ip_base)
  redirector_base_num  = tonumber(local.redirector_ip_octets[3])

  # Parse payload base IP
  payload_ip_octets = split(".", var.payload_ip_base)
  payload_base_num  = tonumber(local.payload_ip_octets[3])

  # Environment-specific settings
  is_lab     = var.environment == "lab"
  is_staging = var.environment == "staging"
  is_ops     = var.environment == "ops"

  # Tags to apply to all resources
  common_tags = merge(var.tags, {
    environment = var.environment
    terraform   = true
    managed_by  = "opentofu"
  })
}

# Data source: Reference template VM
data "proxmox_virtual_environment_vms" "template_vm" {
  node_name = var.proxmox_node
  filter    = "name = '${var.template_name}'"
}

# Output template ID for reference
output "template_id" {
  value       = data.proxmox_virtual_environment_vms.template_vm.virtual_machines[0].vm_id
  description = "Template VM ID retrieved from Proxmox"
}
