data "google_projects" "selected" {
  filter = "projectId:${var.project_id}"
}

data "google_project" "selected" {
  project_id = var.project_id
}

data "google_compute_image" "bastion" {
  project = "debian-cloud"
  family  = "debian-12"
}

locals {
  selected_projects = [
    for project in data.google_projects.selected.projects : project
    if project.project_id == var.project_id
  ]
  selected_project = length(local.selected_projects) == 1 ? local.selected_projects[0] : null
  labels = {
    application = "kordex"
    expires-on  = var.lab_expires_on
    purpose     = "disposable-management-plane-qualification"
    managed-by  = "terraform"
  }
}

# Planning fails closed unless the project is both explicitly allowlisted and
# labeled by its owner. This data-only gate never changes project metadata.
resource "terraform_data" "project_safety" {
  input = var.project_id

  lifecycle {
    precondition {
      condition     = var.project_id != "kordex-fleet-platform"
      error_message = "The shared Kordex product project is prohibited for this lab."
    }
    precondition {
      condition     = contains(var.allowed_project_ids, var.project_id)
      error_message = "project_id is not in allowed_project_ids."
    }
    precondition {
      condition     = var.project_id_confirmation == var.project_id
      error_message = "project_id_confirmation must exactly match project_id."
    }
    precondition {
      condition     = length(local.selected_projects) == 1
      error_message = "The exact selected project could not be read; project metadata access is required."
    }
    precondition {
      condition     = try(local.selected_project.labels["kordex-disposable"], "") == "qualification"
      error_message = "The project owner must designate the project with kordex-disposable=qualification before planning."
    }
    precondition {
      condition     = alltrue([for cidr in [var.subnet_cidr, var.pod_cidr, var.service_cidr, var.master_cidr] : can(cidrnetmask(cidr))])
      error_message = "All VPC, Pod, Service, and master ranges must be valid CIDRs."
    }
  }
}

resource "google_compute_network" "lab" {
  depends_on              = [terraform_data.project_safety]
  name                    = "${var.name_prefix}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Dedicated disposable Kordex private management-plane qualification network."
}

resource "google_compute_subnetwork" "lab" {
  name                     = "${var.name_prefix}-subnet"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.lab.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "${var.name_prefix}-pods"
    ip_cidr_range = var.pod_cidr
  }

  secondary_ip_range {
    range_name    = "${var.name_prefix}-services"
    ip_cidr_range = var.service_cidr
  }
}

resource "google_service_account" "nodes" {
  depends_on   = [terraform_data.project_safety]
  project      = var.project_id
  account_id   = "${var.name_prefix}-nodes"
  display_name = "Kordex disposable management lab GKE nodes"
  description  = "Least-privilege identity for GKE system components; not for application workloads."
}

resource "google_project_iam_member" "nodes" {
  project    = var.project_id
  role       = "roles/container.defaultNodeServiceAccount"
  member     = "serviceAccount:${google_service_account.nodes.email}"
  depends_on = [terraform_data.project_safety]
}

# GKE's managed service agent must be allowed to attach this custom node
# service account to the managed instances; the grant is scoped to this SA.
resource "google_service_account_iam_member" "gke_service_agent_use_nodes" {
  service_account_id = google_service_account.nodes.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:service-${data.google_project.selected.number}@container-engine-robot.iam.gserviceaccount.com"
}

resource "google_artifact_registry_repository" "lab" {
  depends_on    = [terraform_data.project_safety]
  project       = var.project_id
  location      = var.region
  repository_id = "${var.name_prefix}-images"
  description   = "Private, pinned images for the disposable Kordex management-plane lab."
  format        = "DOCKER"
  labels        = local.labels
}

resource "google_artifact_registry_repository_iam_member" "nodes_read_images" {
  project    = var.project_id
  location   = google_artifact_registry_repository.lab.location
  repository = google_artifact_registry_repository.lab.repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.nodes.email}"
}

# Private nodes and private control-plane IP endpoint. NetworkPolicy is
# enforced by Dataplane V2; do not also set the legacy network_policy block.
resource "google_container_cluster" "lab" {
  depends_on                  = [terraform_data.project_safety, google_project_iam_member.nodes, google_service_account_iam_member.gke_service_agent_use_nodes]
  project                     = var.project_id
  name                        = "${var.name_prefix}-gke"
  location                    = var.zone
  network                     = google_compute_network.lab.name
  subnetwork                  = google_compute_subnetwork.lab.name
  networking_mode             = "VPC_NATIVE"
  datapath_provider           = "ADVANCED_DATAPATH"
  remove_default_node_pool    = true
  initial_node_count          = 1
  deletion_protection         = var.cluster_deletion_protection
  enable_intranode_visibility = false

  release_channel {
    channel = "REGULAR"
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "${var.name_prefix}-pods"
    services_secondary_range_name = "${var.name_prefix}-services"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = var.master_cidr

    master_global_access_config {
      enabled = false
    }
  }

  control_plane_endpoints_config {
    dns_endpoint_config {
      allow_external_traffic = false
    }
    ip_endpoints_config {
      enabled = true
    }
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
}

resource "google_container_node_pool" "lab" {
  project        = var.project_id
  name           = "${var.name_prefix}-pool"
  location       = var.zone
  cluster        = google_container_cluster.lab.name
  node_count     = var.node_count
  node_locations = [var.zone]

  management {
    auto_repair  = true
    auto_upgrade = false
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
  }

  node_config {
    machine_type    = var.machine_type
    image_type      = "COS_CONTAINERD"
    disk_type       = "pd-balanced"
    disk_size_gb    = 40
    service_account = google_service_account.nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    labels          = local.labels

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}

resource "google_service_account" "bastion" {
  depends_on   = [terraform_data.project_safety]
  project      = var.project_id
  account_id   = "${var.name_prefix}-iap"
  display_name = "Kordex private lab IAP tunnel bastion"
  description  = "No Google Cloud roles; used only as an SSH tunnel to the private GKE API."
}

resource "google_compute_firewall" "iap_ssh" {
  depends_on    = [terraform_data.project_safety]
  project       = var.project_id
  name          = "${var.name_prefix}-iap-ssh"
  network       = google_compute_network.lab.name
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["${var.name_prefix}-iap"]
  description   = "Allow IAP TCP forwarding to SSH on the no-public-IP lab bastion only."

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_instance" "bastion" {
  depends_on                = [terraform_data.project_safety]
  project                   = var.project_id
  name                      = "${var.name_prefix}-iap"
  zone                      = var.zone
  machine_type              = "e2-micro"
  tags                      = ["${var.name_prefix}-iap"]
  allow_stopping_for_update = true
  deletion_protection       = true
  labels                    = local.labels

  boot_disk {
    initialize_params {
      image = data.google_compute_image.bastion.self_link
      size  = 20
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
    # Intentionally no access_config: the bastion has no external IP.
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  service_account {
    email  = google_service_account.bastion.email
    scopes = []
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
}
