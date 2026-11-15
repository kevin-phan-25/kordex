variable "project_id" {
  description = "Existing dedicated Kordex GCP project ID. This module never creates a project."
  type        = string

  validation {
    condition     = length(var.project_id) >= 6 && !contains(["", "YOUR_PROJECT_ID"], var.project_id)
    error_message = "project_id must be an existing, dedicated GCP project ID."
  }
}

variable "region" {
  description = "Region for the Artifact Registry repository."
  type        = string
  default     = "us-central1"
}

variable "repository_id" {
  description = "Artifact Registry repository ID."
  type        = string
  default     = "kordex"
}

variable "secret_ids" {
  description = "Secret Manager secret containers only; secret payloads are provisioned separately."
  type        = set(string)
  default     = ["kordex-runtime-database-url", "kordex-migration-database-url", "kordex-maintenance-signing-key"]
}

variable "enable_required_apis" {
  description = "Whether to enable Artifact Registry and Secret Manager APIs in the selected project."
  type        = bool
  default     = false
}

variable "labels" {
  description = "Labels applied to supported resources."
  type        = map(string)
  default = {
    application = "kordex"
    managed-by  = "terraform"
  }
}
