locals {
  subnet_cidr = "10.76.0.0/24"
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

# This identity has no project roles. The nodes only need network access to
# download their bootstrap packages; they do not call Google APIs at runtime.
resource "google_service_account" "lab" {
  depends_on   = [terraform_data.project_safety]
  account_id   = "${var.name_prefix}-vm"
  display_name = "Kordex disposable lab VM identity"
  description  = "No IAM roles are granted to this disposable lab identity."
}

resource "google_compute_firewall" "admin" {
  name        = "${var.name_prefix}-admin"
  network     = google_compute_network.lab.name
  description = "Restrict SSH and Kubernetes API ingress to the operator-supplied administrator CIDR."
  direction   = "INGRESS"
  priority    = 1000
  source_ranges = [
    var.admin_cidr,
  ]
  target_tags = ["${var.name_prefix}-server"]

  allow {
    protocol = "tcp"
    ports    = ["22", "6443"]
  }
}

resource "google_compute_firewall" "node_to_node" {
  name        = "${var.name_prefix}-node-to-node"
  network     = google_compute_network.lab.name
  description = "Allow private cluster traffic only between nodes in the dedicated lab subnet."
  direction   = "INGRESS"
  priority    = 1000
  source_ranges = [
    local.subnet_cidr,
  ]
  target_tags = ["${var.name_prefix}-server", "${var.name_prefix}-worker"]

  allow {
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

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
    access_config {}
  }

  metadata = {
    enable-oslogin = "FALSE"
    ssh-keys       = "${var.ssh_user}:${trimspace(var.ssh_public_key)}"
  }
  metadata_startup_script = templatefile("${path.module}/server-startup.sh.tftpl", {
    os_family         = var.os_family
    k3s_version       = var.k3s_version
    k3s_binary_sha256 = var.k3s_binary_sha256
    k3s_token         = var.k3s_token
    ssh_user          = var.ssh_user
  })

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  service_account {
    email  = google_service_account.lab.email
    scopes = []
  }
}

resource "google_compute_instance" "worker" {
  name                      = "${var.name_prefix}-worker"
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

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
    access_config {}
  }

  metadata = {
    enable-oslogin = "FALSE"
    ssh-keys       = "${var.ssh_user}:${trimspace(var.ssh_public_key)}"
  }
  metadata_startup_script = templatefile("${path.module}/worker-startup.sh.tftpl", {
    os_family         = var.os_family
    k3s_version       = var.k3s_version
    k3s_binary_sha256 = var.k3s_binary_sha256
    k3s_token         = var.k3s_token
    server_ip         = google_compute_instance.server.network_interface[0].network_ip
    ssh_user          = var.ssh_user
  })

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  service_account {
    email  = google_service_account.lab.email
    scopes = []
  }
}
