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
  description = "GCP zone for all three disposable Linux VMs."
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
    condition     = var.k3s_version == "v1.36.6+k3s1"
    error_message = "This M3 artifact-approval workflow currently supports only v1.36.6+k3s1."
  }
}

variable "k3s_binary_sha256" {
  description = "SHA-256 extracted only from a successfully verified customer artifact-approval lock for the pinned amd64 K3s binary."
  type        = string

  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.k3s_binary_sha256))
    error_message = "k3s_binary_sha256 must be a lowercase SHA-256 hex digest."
  }
}

variable "k3s_binary_mirror_url" {
  description = "Exact HTTPS URL of the customer-approved K3s binary in the internal artifact mirror on TCP/443; no credentials, query, or fragment."
  type        = string

  validation {
    condition     = can(regex("^https://[A-Za-z0-9.-]+(:443)?(/[A-Za-z0-9._~%+@:-]+)+$", var.k3s_binary_mirror_url)) && !can(regex("^https://([^/]*\\.)?github\\.com(:443)?(/|$)", lower(var.k3s_binary_mirror_url))) && !strcontains(var.k3s_binary_mirror_url, "/../") && !endswith(var.k3s_binary_mirror_url, "/..")
    error_message = "k3s_binary_mirror_url must be a path-only HTTPS URL on TCP/443 on the approved mirror, without credentials, query, fragment, or traversal segments."
  }
}

variable "k3s_system_images_manifest_version" {
  description = "Manifest schema version extracted only after verifying the customer-signed K3s system-image lock."
  type        = string

  validation {
    condition     = var.k3s_system_images_manifest_version == "1"
    error_message = "Only customer-approved K3s system-image manifest version 1 is supported."
  }
}

variable "k3s_system_images_k3s_version" {
  description = "K3s release bound by the customer-signed system-image manifest."
  type        = string

  validation {
    condition     = var.k3s_system_images_k3s_version == "v1.36.6+k3s1"
    error_message = "Only K3s v1.36.6+k3s1 system images are supported by this lab."
  }
}

variable "k3s_system_images_architecture" {
  description = "Architecture bound by the customer-signed system-image manifest."
  type        = string

  validation {
    condition     = var.k3s_system_images_architecture == "linux/amd64"
    error_message = "This lab supports only customer-approved linux/amd64 K3s system images."
  }
}

variable "k3s_system_images_bundle_sha256" {
  description = "SHA-256 of the customer-approved OCI airgap image archive, obtained only from the verified signed manifest."
  type        = string

  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.k3s_system_images_bundle_sha256))
    error_message = "k3s_system_images_bundle_sha256 must be a lowercase SHA-256 hex digest."
  }
}

variable "k3s_system_images_bundle_mirror_url" {
  description = "Exact customer private HTTPS URL bound by the signed manifest for the OCI airgap image archive."
  type        = string

  validation {
    condition = (
      can(regex("^https://[A-Za-z0-9.-]+(:443)?(/[A-Za-z0-9._~%+@:-]+)+$", var.k3s_system_images_bundle_mirror_url)) &&
      !can(regex("^https://([^/]*\\.)?github\\.com(:443)?(/|$)", lower(var.k3s_system_images_bundle_mirror_url))) &&
      !strcontains(var.k3s_system_images_bundle_mirror_url, "/../") &&
      !endswith(var.k3s_system_images_bundle_mirror_url, "/..")
    )
    error_message = "The K3s system-image bundle URL must be a path-only HTTPS URL on the approved private mirror, without credentials, query, fragment, or traversal."
  }
}

variable "k3s_system_images_mirror_host" {
  description = "Private OCI registry host bound by every image reference in the verified customer-signed system-image manifest."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::443)?$", var.k3s_system_images_mirror_host)) && !contains(["docker.io", "registry-1.docker.io", "ghcr.io", "quay.io"], lower(trimsuffix(var.k3s_system_images_mirror_host, ":443")))
    error_message = "k3s_system_images_mirror_host must be a customer-controlled registry hostname and optional port, not a public registry."
  }
}

variable "approved_private_egress_cidrs" {
  description = "Explicit private IPv4 destination ranges for customer-operated package, K3s, image, and management endpoints. These ranges are reachable only on TCP/443 and TCP/18443; no other non-Google HTTPS destinations are allowed from lab VMs."
  type        = set(string)

  validation {
    condition = length(var.approved_private_egress_cidrs) > 0 && alltrue([
      for cidr in var.approved_private_egress_cidrs :
      can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)", cidr)) &&
      can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]{1,2}$", cidr)) &&
      can(cidrhost(cidr, 0)) &&
      tonumber(split(cidr, "/")[1]) >= 24 &&
      cidrhost(cidr, 0) == split(cidr, "/")[0]
    ])
    error_message = "approved_private_egress_cidrs must be a non-empty set of canonical RFC1918 IPv4 CIDRs no broader than /24; public, malformed, overly broad, and host-bit-set ranges are rejected."
  }
}

variable "ubuntu_apt_mirror_url" {
  description = "HTTPS root URL of the customer-operated Ubuntu archive mirror, including noble, noble-updates, noble-backports, and noble-security suites. Its DNS addresses must be covered by approved_private_egress_cidrs."
  type        = string
  default     = ""
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
  description = "Machine type for the K3s server and both Ubuntu workers. Use a larger type only when the test workload needs it."
  type        = string
  default     = "e2-standard-2"
}

variable "boot_disk_size_gb" {
  description = "Linux boot disk size for each of the three VMs."
  type        = number
  default     = 40

  validation {
    condition     = var.boot_disk_size_gb >= 30 && var.boot_disk_size_gb <= 200
    error_message = "boot_disk_size_gb must be between 30 and 200 GiB."
  }
}

