# OpenTofu Variables for Mythic C2 Infrastructure
# Supports lab, staging, and ops deployment modes

variable "environment" {
  description = "Deployment environment: lab, staging, or ops"
  type        = string
  default     = "lab"
  validation {
    condition     = contains(["lab", "staging", "ops"], var.environment)
    error_message = "Environment must be lab, staging, or ops."
  }
}

variable "proxmox_host" {
  description = "Proxmox host URL (https://ip:8006)"
  type        = string
  default     = "https://192.168.36.225:8006"
}

variable "proxmox_username" {
  description = "Proxmox API username (e.g., root@pam)"
  type        = string
  sensitive   = true
}

variable "proxmox_password" {
  description = "Proxmox API password"
  type        = string
  sensitive   = true
}

variable "proxmox_node" {
  description = "Proxmox node name where VMs will be created"
  type        = string
  default     = "pve"
}

# Network Configuration
variable "bridge_vlan_mythic" {
  description = "VLAN tag for Mythic infrastructure (20 for lab/ops)"
  type        = number
  default     = 20
}

variable "bridge_vlan_agents" {
  description = "VLAN tag for agent targets (10 for lab/ops)"
  type        = number
  default     = 10
}

variable "gateway_ip" {
  description = "Gateway IP for the VLAN network"
  type        = string
  default     = "192.168.20.1"
}

variable "dns_servers" {
  description = "DNS servers for lab environment"
  type        = list(string)
  default     = ["192.168.36.100", "8.8.8.8"]
}

# Storage Configuration
variable "storage_pool" {
  description = "Proxmox storage pool for VM disks (local-lvm, local, etc.)"
  type        = string
  default     = "local-lvm"
}

variable "storage_size_gb" {
  description = "Default disk size for VMs (GB)"
  type        = number
  default     = 50
}

variable "snapshot_retention_days" {
  description = "Number of days to retain VM snapshots"
  type        = number
  default     = 7
}

# VM Template Configuration
variable "template_name" {
  description = "Proxmox VM template name (ubuntu-22.04-base)"
  type        = string
  default     = "ubuntu-22.04-base"
}

variable "template_vmid" {
  description = "Template VM ID in Proxmox"
  type        = number
  default     = 9000
}

# Mythic Server Configuration
variable "mythic_vmid" {
  description = "VM ID for Mythic server"
  type        = number
  default     = 100
}

variable "mythic_hostname" {
  description = "Hostname for Mythic server"
  type        = string
  default     = "mythic-01"
}

variable "mythic_ip" {
  description = "IP address for Mythic server (VLAN 20)"
  type        = string
  default     = "192.168.20.10"
}

variable "mythic_cpu_cores" {
  description = "CPU cores for Mythic server"
  type        = number
  default     = 4
}

variable "mythic_memory_mb" {
  description = "RAM for Mythic server (MB)"
  type        = number
  default     = 8192
}

# Redirector Configuration
variable "redirector_count" {
  description = "Number of redirector VMs to create"
  type        = number
  default     = 2
}

variable "redirector_vmid_base" {
  description = "Starting VM ID for redirectors"
  type        = number
  default     = 110
}

variable "redirector_cpu_cores" {
  description = "CPU cores for redirector VMs"
  type        = number
  default     = 2
}

variable "redirector_memory_mb" {
  description = "RAM for redirector VMs (MB)"
  type        = number
  default     = 2048
}

variable "redirector_ip_base" {
  description = "Base IP for redirectors (e.g., 192.168.20.20 creates .20, .21, etc.)"
  type        = string
  default     = "192.168.20.20"
}

# Payload Server Configuration
variable "enable_payload_servers" {
  description = "Enable optional payload staging servers"
  type        = bool
  default     = false
}

variable "payload_count" {
  description = "Number of payload servers"
  type        = number
  default     = 1
}

variable "payload_vmid_base" {
  description = "Starting VM ID for payload servers"
  type        = number
  default     = 120
}

variable "payload_cpu_cores" {
  description = "CPU cores for payload servers"
  type        = number
  default     = 2
}

variable "payload_memory_mb" {
  description = "RAM for payload servers (MB)"
  type        = number
  default     = 4096
}

variable "payload_ip_base" {
  description = "Base IP for payload servers"
  type        = string
  default     = "192.168.20.30"
}

# Echidna Overlay Configuration
variable "echidna_vmid" {
  description = "VM ID for Echidna overlay VM"
  type        = number
  default     = 130
}

variable "echidna_hostname" {
  description = "Hostname for Echidna VM"
  type        = string
  default     = "echidna-01"
}

variable "echidna_ip" {
  description = "IP address for Echidna server"
  type        = string
  default     = "192.168.20.40"
}

variable "echidna_cpu_cores" {
  description = "CPU cores for Echidna VM"
  type        = number
  default     = 2
}

variable "echidna_memory_mb" {
  description = "RAM for Echidna VM (MB)"
  type        = number
  default     = 4096
}

# Monitoring Configuration
variable "enable_monitoring" {
  description = "Enable Prometheus/Grafana monitoring stack"
  type        = bool
  default     = true
}

variable "monitoring_vmid" {
  description = "VM ID for monitoring stack"
  type        = number
  default     = 140
}

variable "monitoring_ip" {
  description = "IP address for monitoring VM"
  type        = string
  default     = "192.168.20.50"
}

variable "monitoring_cpu_cores" {
  description = "CPU cores for monitoring VM"
  type        = number
  default     = 2
}

variable "monitoring_memory_mb" {
  description = "RAM for monitoring VM (MB)"
  type        = number
  default     = 4096
}

# SSH Configuration
variable "ssh_user" {
  description = "Default SSH user for provisioned VMs"
  type        = string
  default     = "ubuntu"
}

variable "ssh_public_key" {
  description = "SSH public key for cloud-init"
  type        = string
  sensitive   = true
}

# Tags and Metadata
variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    project = "mythic"
    iac     = "opentofu"
  }
}

variable "domain" {
  description = "Domain suffix for DNS records (e.g., mythic.lab)"
  type        = string
  default     = "mythic.lab"
}

# Firewall Configuration
variable "enable_ufw" {
  description = "Enable UFW firewall on VMs"
  type        = bool
  default     = true
}

variable "ingress_whitelist" {
  description = "IP addresses allowed for SSH and admin access"
  type        = list(string)
  default     = ["192.168.36.0/24"]
}

# Backup and Snapshot Configuration
variable "enable_automated_snapshots" {
  description = "Enable automated snapshot schedules"
  type        = bool
  default     = true
}

variable "snapshot_schedule" {
  description = "Cron expression for snapshots (daily at 2 AM)"
  type        = string
  default     = "0 2 * * *"
}
