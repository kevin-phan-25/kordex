variable "project_id" {
  description = "Existing dedicated GCP project for a disposable Kordex qualification lab."
  type        = string

  validation {
    condition     = length(var.project_id) >= 6 && !contains(["", "YOUR_PROJECT_ID", "kordex-fleet-platform"], var.project_id)
    error_message = "project_id must name an existing dedicated disposable GCP project; kordex-fleet-platform is prohibited."
  }
}

variable "allowed_project_ids" {
  description = "Explicit allowlist of GCP project IDs approved for disposable Kordex lab resources."
  type        = set(string)

  validation {
    condition     = length(var.allowed_project_ids) > 0 && alltrue([for id in var.allowed_project_ids : length(trimspace(id)) > 0])
    error_message = "allowed_project_ids must contain at least one non-empty, explicitly approved project ID."
  }
}

variable "project_id_confirmation" {
  description = "Second, project-bound confirmation. Set this to exactly project_id after reviewing the project and plan."
  type        = string

  validation {
    condition     = length(trimspace(var.project_id_confirmation)) > 0
    error_message = "project_id_confirmation must be provided after reviewing the disposable project."
  }
}

variable "region" {
  description = "GCP region for the isolated lab network."
  type        = string
  default     = "us-east1"
}

variable "zone" {
  description = "GCP zone for both disposable Linux VMs."
  type        = string
  default     = "us-east1-b"
}

variable "name_prefix" {
  description = "Short prefix for lab resource names."
  type        = string
  default     = "kordex-lab"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,19}$", var.name_prefix))
    error_message = "name_prefix must be 3-20 lowercase letters, digits, or hyphens and start with a letter."
  }
}

variable "upgrade_ssh_user" {
  description = "Local SSH account used later by the in-cluster Kordex executor on the worker; it receives sudo for this disposable lab only."
  type        = string
  default     = "kordex"

  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{0,30}$", var.upgrade_ssh_user))
    error_message = "upgrade_ssh_user must be a valid Linux account name."
  }
}

variable "k3s_version" {
  description = "Pinned K3s release installed on both Linux VMs."
  type        = string
  default     = "v1.36.6+k3s1"

  validation {
    condition     = can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+\\+k3s[0-9]+$", var.k3s_version))
    error_message = "k3s_version must be an exact vX.Y.Z+k3sN release."
  }
}

variable "k3s_binary_sha256" {
  description = "SHA-256 of the amd64 K3s binary for k3s_version from the official release checksum file. Update it whenever k3s_version changes."
  type        = string
  default     = "66ceb8e67edfa547195135d74783bfadc2ecc04a91059e90ae5f70a3dbc98c15"

  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.k3s_binary_sha256))
    error_message = "k3s_binary_sha256 must be a lowercase SHA-256 hex digest."
  }
}

variable "os_family" {
  description = "Host OS family for the disposable worker: debian (Ubuntu 24.04) or rhel (Rocky Linux 9)."
  type        = string
  default     = "debian"

  validation {
    condition     = contains(["debian", "rhel"], var.os_family)
    error_message = "os_family must be debian or rhel."
  }
}

variable "machine_type" {
  description = "Machine type for both lab nodes. Use a larger type only when the test workload needs it."
  type        = string
  default     = "e2-standard-2"
}

variable "boot_disk_size_gb" {
  description = "Linux boot disk size for each VM."
  type        = number
  default     = 40

  validation {
    condition     = var.boot_disk_size_gb >= 30 && var.boot_disk_size_gb <= 200
    error_message = "boot_disk_size_gb must be between 30 and 200 GiB."
  }
}

