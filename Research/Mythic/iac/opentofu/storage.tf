# Storage Configuration for Mythic Infrastructure
# Defines disk policies, snapshot retention, and backup automation

locals {
  # Storage pool selection - local-lvm for lab
  storage_pool = var.storage_pool

  # Default disk size - can be overridden per VM
  disk_size_gb = var.storage_size_gb

  # Snapshot retention policies
  retention_days = var.snapshot_retention_days

  # Environment-specific retention
  is_ops_env = var.environment == "ops"
  retention_ops_days = local.is_ops_env ? 30 : var.snapshot_retention_days
}

# Storage pool reference (data source)
# In production, configure backing storage on Proxmox before running Terraform
data "proxmox_virtual_environment_storage" "storage" {
  storage = local.storage_pool
}

output "storage_pool_info" {
  value = {
    name    = data.proxmox_virtual_environment_storage.storage.storage
    type    = data.proxmox_virtual_environment_storage.storage.type
    content = data.proxmox_virtual_environment_storage.storage.content_types
  }
  description = "Storage pool configuration"
}

# Local variable for disk configuration used in VM modules
locals {
  disk_config = {
    pool      = local.storage_pool
    size      = local.disk_size_gb
    format    = "raw"  # Proxmox default for LVM
    backup    = true   # Enable backups
    replicate = false  # Set to true for HA cluster
  }

  # Snapshot policy definition
  snapshot_policy = {
    retention_days = local.retention_ops_days
    enabled        = var.enable_automated_snapshots
    schedule       = var.snapshot_schedule
    # Cron: "0 2 * * *" = 2 AM daily
  }
}

# Output disk configuration for VM modules
output "disk_config" {
  value = {
    pool        = local.disk_config.pool
    size_gb     = local.disk_config.size
    format      = local.disk_config.format
    backup      = local.disk_config.backup
    replicate   = local.disk_config.replicate
  }
  description = "Standard disk configuration for all VMs"
}

output "snapshot_policy" {
  value = {
    enabled        = local.snapshot_policy.enabled
    retention_days = local.snapshot_policy.retention_days
    schedule       = local.snapshot_policy.schedule
  }
  description = "Snapshot retention policy"
}

# Backup strategy notes:
# Lab environment:
#   - Local snapshots: 7-day retention
#   - Manual backup to Proxmox storage or external NFS
# Staging/Ops environment:
#   - VM snapshots: 30-day rolling retention
#   - Daily incremental backups to dedicated backup storage
#   - Monthly full backups exported to cold storage
# Note: Configure backup jobs in Proxmox directly or via ansible/backup.yml

locals {
  backup_strategy = {
    lab = {
      snapshot_retention = 7
      backup_frequency   = "manual"
      backup_target      = "local"
      backup_encryption  = false
    }
    staging = {
      snapshot_retention = 14
      backup_frequency   = "daily"
      backup_target      = "backup-nfs"
      backup_encryption  = true
    }
    ops = {
      snapshot_retention = 30
      backup_frequency   = "daily"
      backup_target      = "backup-nfs"
      backup_encryption  = true
    }
  }

  # Select backup strategy for current environment
  active_backup_strategy = local.backup_strategy[var.environment]
}

output "backup_strategy" {
  value = {
    environment       = var.environment
    snapshot_retention = local.active_backup_strategy.snapshot_retention
    backup_frequency  = local.active_backup_strategy.backup_frequency
    backup_target     = local.active_backup_strategy.backup_target
    backup_encryption = local.active_backup_strategy.backup_encryption
  }
  description = "Backup strategy for current environment"
}

# VM-specific storage notes (used in vm_*.tf):
# - Mythic server: 50 GB SSD + persistent /var/lib/postgresql for database
# - Redirectors: 20 GB SSD (stateless, easy to rebuild)
# - Payload servers: 30 GB SSD + /opt/payloads (can use NFS mount)
# - Echidna: 30 GB SSD
# - Monitoring: 50 GB SSD + /var/lib/prometheus persistent storage

locals {
  vm_storage_sizes = {
    mythic      = 50    # Large for database + container images
    redirector  = 20    # Stateless
    payload     = 30    # For file hosting
    echidna     = 30    # For overlay network
    monitoring  = 50    # For Prometheus time-series data
  }
}

output "vm_storage_allocation" {
  value = {
    mythic_gb      = local.vm_storage_sizes.mythic
    redirector_gb  = local.vm_storage_sizes.redirector
    payload_gb     = local.vm_storage_sizes.payload
    echidna_gb     = local.vm_storage_sizes.echidna
    monitoring_gb  = local.vm_storage_sizes.monitoring
  }
  description = "Storage allocation per VM type (GB)"
}
