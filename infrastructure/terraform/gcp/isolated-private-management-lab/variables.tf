variable "project_id" {
  description = "Existing, separately approved disposable project. Product and shared projects are prohibited."
  type        = string

  validation {
    condition     = length(var.project_id) >= 6 && !contains(["", "YOUR_PROJECT_ID", "kordex-fleet-platform"], var.project_id)
    error_message = "project_id must be a separate disposable project; kordex-fleet-platform is prohibited."
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
    condition     = can(regex("^[a-z][a-z0-9-]{2,19}$", var.name_prefix))
    error_message = "name_prefix must be 3-20 lowercase letters, digits, or hyphens and start with a letter."
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
}

variable "zone" {
  description = "Single zone for this disposable, non-HA qualification cluster."
  type        = string
  default     = "us-east1-b"
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
}

variable "pod_cidr" {
  description = "Dedicated VPC-native Pod secondary range."
  type        = string
  default     = "10.88.0.0/16"
}

variable "service_cidr" {
  description = "Dedicated VPC-native Service secondary range."
  type        = string
  default     = "10.90.0.0/20"
}

variable "master_cidr" {
  description = "Dedicated private control-plane range. Must not overlap the VPC, Pod, or Service ranges."
  type        = string
  default     = "172.20.0.0/28"
}

variable "cluster_deletion_protection" {
  description = "Keep true during operation. To destroy intentionally, review backups and first apply a separate change setting this false."
  type        = bool
  default     = true
}
