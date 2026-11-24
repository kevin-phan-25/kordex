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

variable "terraform_principal_email" {
  description = "Customer-approved service account impersonated by the Google provider for every M3 plan/apply operation. This is a non-secret identity binding."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._%+-]{4,127}@[A-Za-z0-9.-]+\\.iam\\.gserviceaccount\\.com$", var.terraform_principal_email))
    error_message = "terraform_principal_email must be the exact customer-approved Google service account identity."
  }
}

variable "server_service_account_id" {
  description = "Customer-created server runtime identity. The Terraform principal must have roles/iam.serviceAccountUser on this exact account."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.server_service_account_id))
    error_message = "server_service_account_id must be the exact approved lab server service-account ID."
  }
}

variable "worker_service_account_id" {
  description = "Customer-created worker runtime identity. The Terraform principal must have roles/iam.serviceAccountUser on this exact account."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.worker_service_account_id))
    error_message = "worker_service_account_id must be the exact approved lab worker service-account ID."
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

variable "recovery_snapshot_ids" {
  description = "Optional complete server/worker-1/worker-2 recovery snapshot set used only by the guarded restore workflow."
  type        = map(string)
  default     = {}

  validation {
    condition = (length(var.recovery_snapshot_ids) == 0) || (
      toset(keys(var.recovery_snapshot_ids)) == toset(["server", "worker-1", "worker-2"]) &&
      alltrue([for snapshot in values(var.recovery_snapshot_ids) : length(snapshot) <= 63 && can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", snapshot))])
    )
    error_message = "recovery_snapshot_ids must be empty or name exactly server, worker-1, and worker-2 with valid snapshot IDs."
  }
}

variable "recovery_project_id" {
  description = "Project identity bound to a guarded recovery snapshot set; empty outside a restore configuration."
  type        = string
  default     = ""
}

variable "recovery_lab_id" {
  description = "Lab identity bound to a guarded recovery snapshot set; empty outside a restore configuration."
  type        = string
  default     = ""
}

variable "recovery_zone" {
  description = "Zone bound to a guarded recovery snapshot set; empty outside a restore configuration."
  type        = string
  default     = ""
}

variable "recovery_internal_ips" {
  description = "Original private addresses for the complete recovery snapshot set; supplied only by the guarded restore workflow."
  type        = map(string)
  default     = {}

  validation {
    condition = (length(var.recovery_internal_ips) == 0) || (
      toset(keys(var.recovery_internal_ips)) == toset(["server", "worker-1", "worker-2"]) &&
      length(toset(values(var.recovery_internal_ips))) == 3 &&
      alltrue([for address in values(var.recovery_internal_ips) : can(cidrhost("${address}/32", 0)) && can(regex("^10\\.76\\.0\\.([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$", address))])
    )
    error_message = "recovery_internal_ips must be empty or contain the three original private lab addresses."
  }
}

variable "recovery_operation_id" {
  description = "Twelve lowercase hexadecimal characters binding newly restored boot disks to one guarded reset."
  type        = string
  default     = ""

  validation {
    condition     = (length(var.recovery_snapshot_ids) == 0 && var.recovery_operation_id == "") || (length(var.recovery_snapshot_ids) == 3 && can(regex("^[a-f0-9]{12}$", var.recovery_operation_id)))
    error_message = "recovery_operation_id is required and must be 12 lowercase hexadecimal characters when restoring snapshots."
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

variable "approved_private_mirror_cidrs" {
  description = "Explicit private IPv4 destination ranges for customer-operated Ubuntu, K3s binary, OCI, and package mirrors. Reachable only on TCP/443."
  type        = set(string)

  validation {
    condition = length(var.approved_private_mirror_cidrs) > 0 && alltrue([
      for cidr in var.approved_private_mirror_cidrs :
      can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)", cidr)) &&
      can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]{1,2}$", cidr)) &&
      can(cidrhost(cidr, 0)) &&
      tonumber(split(cidr, "/")[1]) >= 24 &&
      cidrhost(cidr, 0) == split(cidr, "/")[0]
    ])
    error_message = "approved_private_mirror_cidrs must be a non-empty set of canonical RFC1918 IPv4 CIDRs no broader than /24; public, malformed, overly broad, and host-bit-set ranges are rejected."
  }
}

variable "approved_private_relay_cidrs" {
  description = "Explicit private IPv4 destination ranges containing the workstation mTLS relay addresses. Reachable only on TCP/18443."
  type        = set(string)

  validation {
    condition = length(var.approved_private_relay_cidrs) > 0 && alltrue([
      for cidr in var.approved_private_relay_cidrs :
      can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)", cidr)) &&
      can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]{1,2}$", cidr)) &&
      can(cidrhost(cidr, 0)) &&
      tonumber(split(cidr, "/")[1]) >= 24 &&
      cidrhost(cidr, 0) == split(cidr, "/")[0]
    ])
    error_message = "approved_private_relay_cidrs must be a non-empty set of canonical RFC1918 IPv4 CIDRs no broader than /24; public, malformed, overly broad, and host-bit-set ranges are rejected."
  }
}

variable "ubuntu_apt_mirror_url" {
  description = "HTTPS root URL of the customer-operated Ubuntu archive mirror, including noble, noble-updates, noble-backports, and noble-security suites. Its DNS addresses must be covered by approved_private_mirror_cidrs."
  type        = string
  default     = ""
}

variable "debian_archive_mirror_url" {
  description = "HTTPS root URL of the customer-operated Debian 13 archive mirror for trixie and trixie-updates. Its DNS addresses must be covered by approved_private_mirror_cidrs."
  type        = string
  default     = ""
}

variable "debian_security_mirror_url" {
  description = "HTTPS root URL of the customer-operated Debian 13 security mirror for trixie-security. Its DNS addresses must be covered by approved_private_mirror_cidrs."
  type        = string
  default     = ""
}

variable "qualification_os_profile" {
  description = "Required selected profile: Debian 13 qualification or customer-approved exact RHEL 9 image with minor >=9.8. Ubuntu 24.04 is supplemental only."
  type        = string

  validation {
    condition     = contains(["ubuntu-24.04", "debian-13", "rhel-9"], var.qualification_os_profile)
    error_message = "qualification_os_profile must explicitly select debian-13 or rhel-9 for canonical M3; ubuntu-24.04 is supplemental only."
  }
}

variable "qualification_os_minor" {
  description = "Exact RHEL minor release selected by the approved package policy; required for RHEL 9 and must be >=8. Empty for Ubuntu/Debian profiles."
  type        = string
  default     = ""

  validation {
    condition = (
      (var.qualification_os_profile == "rhel-9" &&
        can(regex("^(8|9|[1-9][0-9]+)$", var.qualification_os_minor)) &&
      try(tonumber(var.qualification_os_minor), 0) >= 8) ||
      (var.qualification_os_profile != "rhel-9" && var.qualification_os_minor == "")
    )
    error_message = "qualification_os_minor must be the selected RHEL 9 minor >=8, and must be empty for other profiles."
  }
}

variable "qualification_os_point_release" {
  description = "Exact package-policy OS release: current Debian 13 stable point (for example 13.8) or selected RHEL 9 minor (for example 9.9); empty for supplemental Ubuntu."
  type        = string
  default     = ""

  validation {
    condition = (
      (var.qualification_os_profile == "debian-13" &&
      can(regex("^13\\.[0-9]+$", var.qualification_os_point_release))) ||
      (var.qualification_os_profile == "rhel-9" &&
      var.qualification_os_point_release == "9.${var.qualification_os_minor}") ||
      (var.qualification_os_profile == "ubuntu-24.04" && var.qualification_os_point_release == "")
    )
    error_message = "qualification_os_point_release must bind the selected Debian 13 point or RHEL 9 minor; Ubuntu supplemental runs leave it empty."
  }
}

variable "qualification_image_approval_reference" {
  description = "Non-secret customer image-owner approval record reference binding the exact image self-link to OS identity, point/minor release, and linux/amd64. Independent human review is still required."
  type        = string
  default     = ""

  validation {
    condition     = var.qualification_image_approval_reference == "" || can(regex("^[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}$", var.qualification_image_approval_reference))
    error_message = "qualification_image_approval_reference must identify the separately reviewed image approval record."
  }
}

variable "qualification_image_approval_sha256" {
  description = "SHA-256 of the canonical customer image-owner approval record bound to this reviewed plan. It is a binding, not proof of independent review."
  type        = string
  default     = ""

  validation {
    condition     = var.qualification_image_approval_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.qualification_image_approval_sha256))
    error_message = "qualification_image_approval_sha256 must be the canonical image approval record digest."
  }
}

variable "qualification_image_unique_id" {
  description = "Google server-assigned numeric image ID independently recorded by the image owner and checked against metadata during planning. Empty only for supplemental Ubuntu."
  type        = string
  default     = ""

  validation {
    condition     = var.qualification_os_profile == "ubuntu-24.04" ? var.qualification_image_unique_id == "" : can(regex("^[1-9][0-9]{0,19}$", var.qualification_image_unique_id))
    error_message = "Debian/RHEL qualification requires the exact server-assigned Compute Engine image ID; supplemental Ubuntu leaves this field empty."
  }
}

variable "debian_image_self_link" {
  description = "Exact image self-link resolved and approved by the Debian image owner. Image families are not accepted for M3 qualification planning."
  type        = string
  default     = ""
}

variable "rhel_image_self_link" {
  description = "Exact customer-approved Google Compute Engine RHEL 9 image self-link, never an image family. The resolved image is recorded in the plan and qualification evidence."
  type        = string
  default     = ""
}

variable "rhel_repository_baseurl" {
  description = "Customer-controlled HTTPS private RPM repository URL with signed metadata for the selected RHEL minor and x86_64. Its DNS addresses must be covered by approved_private_mirror_cidrs."
  type        = string
  default     = ""
}

variable "rhel_repository_gpg_key_path" {
  description = "Absolute path to the independently delivered customer-approved RPM repository signing public key already present in the approved RHEL image."
  type        = string
  default     = ""
}

variable "rhel_repository_gpg_fingerprint" {
  description = "40-character uppercase or lowercase OpenPGP fingerprint independently confirmed by the customer trust custodian."
  type        = string
  default     = ""
}

variable "os_family" {
  description = "Maintenance policy OS family; debian for Ubuntu/Debian and rhel for RHEL."
  type        = string
  default     = "debian"

  validation {
    condition     = contains(["debian", "rhel"], var.os_family)
    error_message = "os_family must be debian or rhel."
  }
}

variable "machine_type" {
  description = "Machine type for the K3s server and both selected-profile workers. Use a larger type only when the test workload needs it."
  type        = string
  default     = "e2-medium"
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

