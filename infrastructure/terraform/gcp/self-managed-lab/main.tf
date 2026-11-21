locals {
  subnet_cidr                = "10.76.0.0/24"
  iap_tcp_cidr               = "35.235.240.0/20"
  restricted_googleapis_cidr = "199.36.153.4/30"
  worker_vm_names = {
    worker-1 = "${var.name_prefix}-worker"
    worker-2 = "${var.name_prefix}-worker-2"
  }
  labels = {
    application = "kordex"
    purpose     = "disposable-qualification"
    managed-by  = "terraform"
  }
}

# Resolve the live project metadata before any lab resource can be created.
# The explicit project ID filter limits the result to the selected project;
# missing access or a missing project fails closed in the safety preconditions.
data "google_projects" "lab" {
  filter = "projectId:${var.project_id}"
}

locals {
  selected_projects = [
    for project in data.google_projects.lab.projects : project
    if project.project_id == var.project_id
  ]
  selected_project = length(local.selected_projects) == 1 ? local.selected_projects[0] : null
}

# This resource is an apply/plan gate only; it does not alter the project.
# The project label must be applied and reviewed separately by the project
# owner, and project_id_confirmation must be entered independently of the
# allowlist before Terraform is permitted to create lab resources.
resource "terraform_data" "project_safety" {
  input = var.project_id

  lifecycle {
    precondition {
      condition     = var.project_id != "kordex-fleet-platform"
      error_message = "Refusing lab provisioning: kordex-fleet-platform is a product project and must never be used for qualification resources."
    }

    precondition {
      condition     = contains(var.allowed_project_ids, var.project_id)
      error_message = "Refusing lab provisioning: project_id is not in allowed_project_ids."
    }

    precondition {
      condition     = var.project_id_confirmation == var.project_id
      error_message = "Refusing lab provisioning: project_id_confirmation must exactly match project_id."
    }

    precondition {
      condition     = length(local.selected_projects) == 1
      error_message = "Refusing lab provisioning: the exact GCP project could not be read; grant project metadata read access and retry."
    }

    precondition {
      condition     = try(local.selected_project.labels["kordex-disposable"], "") == "qualification"
      error_message = "Refusing lab provisioning: the live GCP project must have label kordex-disposable=qualification."
    }

    precondition {
      condition = var.os_family == "debian" && can(regex(
        "^https://[A-Za-z0-9.-]+(:443)?(/[A-Za-z0-9._~%+@:-]+)*$",
        var.ubuntu_apt_mirror_url
      ))
      error_message = "This private M3 lab profile requires Ubuntu 24.04 and a path-only HTTPS Ubuntu mirror URL; RHEL repository bootstrap is not configured."
    }

    precondition {
      condition = (
        var.k3s_system_images_k3s_version == var.k3s_version &&
        var.k3s_system_images_manifest_version == "1" &&
        var.k3s_system_images_architecture == "linux/amd64" &&
        (endswith(var.k3s_system_images_bundle_mirror_url, "/k3s/${var.k3s_version}/linux-amd64/${var.k3s_system_images_bundle_sha256}/k3s-airgap-images-amd64.tar") ||
        endswith(var.k3s_system_images_bundle_mirror_url, "/k3s/v1.36.6%2Bk3s1/linux-amd64/${var.k3s_system_images_bundle_sha256}/k3s-airgap-images-amd64.tar"))
      )
      error_message = "Refusing lab bootstrap: the approved system-image manifest, K3s release, and VM architecture must match exactly."
    }
  }
}

# Resolve the selected moving OS image family once during planning. The saved
# Terraform plan then carries a concrete image self-link for both VMs.
data "google_compute_image" "ubuntu_2404" {
  count   = var.os_family == "debian" ? 1 : 0
  project = "ubuntu-os-cloud"
  family  = "ubuntu-2404-lts-amd64"
}

data "google_compute_image" "rocky_9" {
  count   = var.os_family == "rhel" ? 1 : 0
  project = "rocky-linux-cloud"
  family  = "rocky-linux-9"
}

locals {
  boot_image = var.os_family == "debian" ? data.google_compute_image.ubuntu_2404[0].self_link : data.google_compute_image.rocky_9[0].self_link
}

resource "google_compute_network" "lab" {
  depends_on              = [terraform_data.project_safety]
  name                    = "${var.name_prefix}-network"
  auto_create_subnetworks = false
  description             = "Isolated network for disposable Kordex self-managed upgrade qualification."
}

resource "google_compute_subnetwork" "lab" {
  name                     = "${var.name_prefix}-subnet"
  region                   = var.region
  network                  = google_compute_network.lab.id
  ip_cidr_range            = local.subnet_cidr
  private_ip_google_access = true
}

# Private Google Access needs DNS to resolve Google API names to the restricted
# VIP. This keeps runtime Secret Manager access off arbitrary public HTTPS.
# dns.googleapis.com must be enabled separately by an authorized project owner.
resource "google_dns_managed_zone" "restricted_googleapis" {
  depends_on  = [terraform_data.project_safety]
  name        = "${var.name_prefix}-googleapis"
  dns_name    = "googleapis.com."
  description = "Private DNS mapping for restricted Google APIs used by the disposable lab."
  visibility  = "private"
  labels      = local.labels

  private_visibility_config {
    networks {
      network_url = google_compute_network.lab.id
    }
  }
}

resource "google_dns_record_set" "restricted_googleapis_a" {
  name         = "restricted.googleapis.com."
  managed_zone = google_dns_managed_zone.restricted_googleapis.name
  type         = "A"
  ttl          = 300
  rrdatas      = ["199.36.153.4", "199.36.153.5", "199.36.153.6", "199.36.153.7"]
}

resource "google_dns_record_set" "restricted_googleapis_wildcard" {
  name         = "*.googleapis.com."
  managed_zone = google_dns_managed_zone.restricted_googleapis.name
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["restricted.googleapis.com."]
}

# The token value is created at runtime by the K3s server. Terraform stores
# only this empty secret's metadata and resource name, never a secret version.
resource "google_secret_manager_secret" "agent_join" {
  depends_on = [terraform_data.project_safety]
  secret_id  = "${var.name_prefix}-agent-join"
  project    = var.project_id
  labels     = local.labels
  ttl        = "14400s"

  replication {
    auto {}
  }
}

# Separate VM identities; neither has project-level roles. The server can
# publish/destroy a version on this one secret, and the worker can only read it.
resource "google_service_account" "server" {
  depends_on   = [terraform_data.project_safety]
  account_id   = "${var.name_prefix}-server"
  display_name = "Kordex disposable K3s server identity"
  description  = "Secret version management is limited to this lab's expiring K3s agent join secret."
}

# Server role is scoped to one secret. Worker receives access but cannot write
# or administer versions.
resource "google_secret_manager_secret_iam_member" "server_versions" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.agent_join.secret_id
  role      = "roles/secretmanager.secretVersionManager"
  member    = "serviceAccount:${google_service_account.server.email}"
}

resource "google_service_account" "worker" {
  depends_on   = [terraform_data.project_safety]
  account_id   = "${var.name_prefix}-worker"
  display_name = "Kordex disposable K3s worker identity"
  description  = "Can read only this lab's short-lived K3s agent join token."
}

resource "google_secret_manager_secret_iam_member" "worker_secret_access" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.agent_join.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_secret_manager_secret_iam_member" "worker_version_metadata" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.agent_join.secret_id
  role      = "roles/secretmanager.viewer"
  member    = "serviceAccount:${google_service_account.worker.email}"
}

# IAP TCP forwarding only; no public SSH or RDP path exists.
resource "google_compute_firewall" "admin" {
  name          = "${var.name_prefix}-admin"
  network       = google_compute_network.lab.name
  description   = "Allow SSH administration only through Google's IAP TCP forwarding range."
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = [local.iap_tcp_cidr]
  target_tags   = ["${var.name_prefix}-server", "${var.name_prefix}-worker"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "node_to_node" {
  name        = "${var.name_prefix}-node-to-node"
  network     = google_compute_network.lab.name
  description = "Allow only K3s, kubelet, Flannel, and SSH traffic inside the dedicated lab subnet."
  direction   = "INGRESS"
  priority    = 1000
  source_ranges = [
    local.subnet_cidr,
  ]
  target_tags = ["${var.name_prefix}-server", "${var.name_prefix}-worker"]

  allow {
    protocol = "tcp"
    ports    = ["22", "6443", "10250"]
  }

  allow {
    protocol = "udp"
    ports    = ["8472"]
  }
}

resource "google_compute_firewall" "egress_internal" {
  name               = "${var.name_prefix}-egress-internal"
  network            = google_compute_network.lab.name
  direction          = "EGRESS"
  priority           = 800
  destination_ranges = [local.subnet_cidr]
  target_tags        = ["${var.name_prefix}-server", "${var.name_prefix}-worker"]

  allow {
    protocol = "all"
  }
}

resource "google_compute_firewall" "egress_dns" {
  name               = "${var.name_prefix}-egress-dns"
  network            = google_compute_network.lab.name
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = ["169.254.169.254/32"]
  target_tags        = ["${var.name_prefix}-server", "${var.name_prefix}-worker"]

  allow {
    protocol = "tcp"
    ports    = ["53"]
  }
  allow {
    protocol = "udp"
    ports    = ["53"]
  }
}

resource "google_compute_firewall" "egress_private_services" {
  name               = "${var.name_prefix}-egress-private-services"
  network            = google_compute_network.lab.name
  description        = "Allow mirror HTTPS on TCP/443 and workstation relay TLS on TCP/18443 only to explicitly supplied private customer service CIDRs."
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = tolist(var.approved_private_egress_cidrs)
  target_tags        = ["${var.name_prefix}-server", "${var.name_prefix}-worker"]

  allow {
    protocol = "tcp"
    ports    = ["443", "18443"]
  }
}

resource "google_compute_firewall" "egress_restricted_googleapis" {
  name               = "${var.name_prefix}-egress-restricted-googleapis"
  network            = google_compute_network.lab.name
  description        = "Allow HTTPS only to the restricted Google APIs VIP used by the runtime Secret Manager bootstrap."
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = [local.restricted_googleapis_cidr]
  target_tags        = ["${var.name_prefix}-server", "${var.name_prefix}-worker"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "egress_deny_other" {
  name               = "${var.name_prefix}-egress-deny-other"
  network            = google_compute_network.lab.name
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["${var.name_prefix}-server", "${var.name_prefix}-worker"]

  deny {
    protocol = "all"
  }
}

resource "google_compute_instance" "server" {
  name                      = "${var.name_prefix}-server"
  zone                      = var.zone
  machine_type              = var.machine_type
  allow_stopping_for_update = true
  deletion_protection       = false
  tags                      = ["${var.name_prefix}-server"]
  labels                    = local.labels

  boot_disk {
    initialize_params {
      image = local.boot_image
      size  = var.boot_disk_size_gb
      type  = "pd-balanced"
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.server_versions]

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
  }

  metadata = {
    enable-oslogin           = "TRUE"
    block-project-ssh-keys   = "TRUE"
    disable-legacy-endpoints = "TRUE"
  }
  metadata_startup_script = templatefile("${path.module}/server-startup.sh.tftpl", {
    os_family                           = var.os_family
    ubuntu_apt_mirror_url               = var.ubuntu_apt_mirror_url
    k3s_version                         = var.k3s_version
    k3s_binary_sha256                   = var.k3s_binary_sha256
    k3s_binary_mirror_url               = var.k3s_binary_mirror_url
    k3s_system_images_manifest_version  = var.k3s_system_images_manifest_version
    k3s_system_images_k3s_version       = var.k3s_system_images_k3s_version
    k3s_system_images_architecture      = var.k3s_system_images_architecture
    k3s_system_images_bundle_sha256     = var.k3s_system_images_bundle_sha256
    k3s_system_images_bundle_mirror_url = var.k3s_system_images_bundle_mirror_url
    k3s_system_images_mirror_host       = var.k3s_system_images_mirror_host
    project_id                          = var.project_id
    secret_id                           = google_secret_manager_secret.agent_join.secret_id
    worker_names                        = [local.worker_vm_names["worker-1"], local.worker_vm_names["worker-2"]]
    upgrade_ssh_user                    = var.upgrade_ssh_user
    secret_helper                       = file("${path.module}/secret_manager_bootstrap.py")
  })

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  service_account {
    email  = google_service_account.server.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}

resource "google_compute_instance" "worker" {
  for_each                  = local.worker_vm_names
  name                      = each.value
  zone                      = var.zone
  machine_type              = var.machine_type
  allow_stopping_for_update = true
  deletion_protection       = false
  tags                      = ["${var.name_prefix}-worker"]
  labels                    = local.labels

  boot_disk {
    initialize_params {
      image = local.boot_image
      size  = var.boot_disk_size_gb
      type  = "pd-balanced"
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.worker_secret_access,
    google_secret_manager_secret_iam_member.worker_version_metadata,
  ]

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
  }

  metadata = {
    enable-oslogin           = "TRUE"
    block-project-ssh-keys   = "TRUE"
    disable-legacy-endpoints = "TRUE"
  }
  metadata_startup_script = templatefile("${path.module}/worker-startup.sh.tftpl", {
    os_family                           = var.os_family
    ubuntu_apt_mirror_url               = var.ubuntu_apt_mirror_url
    k3s_version                         = var.k3s_version
    k3s_binary_sha256                   = var.k3s_binary_sha256
    k3s_binary_mirror_url               = var.k3s_binary_mirror_url
    k3s_system_images_manifest_version  = var.k3s_system_images_manifest_version
    k3s_system_images_k3s_version       = var.k3s_system_images_k3s_version
    k3s_system_images_architecture      = var.k3s_system_images_architecture
    k3s_system_images_bundle_sha256     = var.k3s_system_images_bundle_sha256
    k3s_system_images_bundle_mirror_url = var.k3s_system_images_bundle_mirror_url
    k3s_system_images_mirror_host       = var.k3s_system_images_mirror_host
    server_ip                           = google_compute_instance.server.network_interface[0].network_ip
    project_id                          = var.project_id
    secret_id                           = google_secret_manager_secret.agent_join.secret_id
    worker_name                         = each.value
    secret_helper                       = file("${path.module}/secret_manager_bootstrap.py")
    upgrade_ssh_user                    = var.upgrade_ssh_user
  })

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  service_account {
    email  = google_service_account.worker.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}

# Preserve the original single worker VM as worker-1 when an existing Terraform
# state is upgraded to the two-worker topology.
moved {
  from = google_compute_instance.worker
  to   = google_compute_instance.worker["worker-1"]
}
