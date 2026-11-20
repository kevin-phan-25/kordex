variable "project_id" {
  description = "Existing, separately approved disposable project. Product and shared projects are prohibited."
  type        = string

  validation {
    condition     = can(regex("^kordex-pmlab-[a-z][a-z0-9-]{3,15}[a-z0-9]$", var.project_id)) && var.project_id != "kordex-fleet-platform"
    error_message = "project_id must use the dedicated kordex-pmlab-<unique-suffix> naming convention; kordex-fleet-platform is prohibited."
  }
}

variable "allowed_project_ids" {
  description = "Explicit project ID allowlist reviewed for this disposable lab."
  type        = set(string)

  validation {
    condition     = length(var.allowed_project_ids) > 0 && alltrue([for id in var.allowed_project_ids : length(trimspace(id)) > 0])
    error_message = "allowed_project_ids must contain the explicitly approved project ID."
  }
}

variable "project_id_confirmation" {
  description = "Second confirmation; must exactly match project_id after project review."
  type        = string

  validation {
    condition     = length(trimspace(var.project_id_confirmation)) > 0
    error_message = "project_id_confirmation is required."
  }
}

variable "name_prefix" {
  description = "Prefix for all lab resources."
  type        = string
  default     = "kordex-pmlab"

  validation {
    condition     = var.name_prefix == "kordex-pmlab"
    error_message = "name_prefix is fixed to kordex-pmlab so this module can only target its dedicated cluster and resources."
  }
}

variable "lab_expires_on" {
  description = "Review date in YYYY-MM-DD format; applied as a label, not an automatic destroy date."
  type        = string

  validation {
    condition     = can(regex("^20[0-9]{2}-[0-9]{2}-[0-9]{2}$", var.lab_expires_on))
    error_message = "lab_expires_on must use YYYY-MM-DD format."
  }
}

variable "region" {
  description = "Region for VPC resources and Artifact Registry."
  type        = string
  default     = "us-east1"

  validation {
    condition     = var.region == "us-east1"
    error_message = "region is fixed to the reviewed us-east1 lab location."
  }
}

variable "zone" {
  description = "Single zone for this disposable, non-HA qualification cluster."
  type        = string
  default     = "us-east1-b"

  validation {
    condition     = var.zone == "us-east1-b" && startswith(var.zone, "${var.region}-")
    error_message = "zone is fixed to the reviewed us-east1-b lab location."
  }
}

variable "node_count" {
  description = "Use one node for a low-cost functional lab or three for node-loss/rescheduling experiments."
  type        = number
  default     = 1

  validation {
    condition     = contains([1, 3], var.node_count)
    error_message = "node_count must be 1 or 3."
  }
}

variable "machine_type" {
  description = "Use e2-standard-4 for one node or e2-standard-2 for three nodes."
  type        = string
  default     = "e2-standard-4"

  validation {
    condition     = (var.node_count == 1 && var.machine_type == "e2-standard-4") || (var.node_count == 3 && var.machine_type == "e2-standard-2")
    error_message = "Use one e2-standard-4 node or three e2-standard-2 nodes; these combinations are sized for the management-plane lab."
  }
}

variable "subnet_cidr" {
  description = "Node and IAP bastion subnet."
  type        = string
  default     = "10.84.0.0/20"

  validation {
    condition     = var.subnet_cidr == "10.84.0.0/20"
    error_message = "subnet_cidr is fixed to the reviewed isolated-lab range."
  }
}

variable "pod_cidr" {
  description = "Dedicated VPC-native Pod secondary range."
  type        = string
  default     = "10.88.0.0/16"

  validation {
    condition     = var.pod_cidr == "10.88.0.0/16"
    error_message = "pod_cidr is fixed to the reviewed isolated-lab range."
  }
}

variable "service_cidr" {
  description = "Dedicated VPC-native Service secondary range."
  type        = string
  default     = "10.90.0.0/20"

  validation {
    condition     = var.service_cidr == "10.90.0.0/20"
    error_message = "service_cidr is fixed to the reviewed isolated-lab range."
  }
}

variable "master_cidr" {
  description = "Dedicated private control-plane range. Must not overlap the VPC, Pod, or Service ranges."
  type        = string
  default     = "172.20.0.0/28"

  validation {
    condition     = var.master_cidr == "172.20.0.0/28"
    error_message = "master_cidr is fixed to the reviewed isolated-lab range."
  }
}

variable "cluster_deletion_protection" {
  description = "Keep true during operation. To destroy intentionally, review backups and first apply a separate change setting this false."
  type        = bool
  default     = true
}
