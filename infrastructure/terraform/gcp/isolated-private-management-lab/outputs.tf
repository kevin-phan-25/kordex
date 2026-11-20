output "project_id" {
  value = var.project_id
}

output "cluster_name" {
  value = google_container_cluster.lab.name
}

output "cluster_location" {
  value = google_container_cluster.lab.location
}

output "private_control_plane_endpoint" {
  value       = google_container_cluster.lab.private_cluster_config[0].private_endpoint
  description = "Private IP endpoint; reachable from the IAP bastion, not directly from the workstation."
}

output "bastion_name" {
  value = google_compute_instance.bastion.name
}

output "bastion_zone" {
  value = google_compute_instance.bastion.zone
}

output "artifact_registry_repository" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.lab.repository_id}"
}

output "node_service_account" {
  value = google_service_account.nodes.email
}

output "suggested_get_credentials_command" {
  value = "gcloud container clusters get-credentials ${google_container_cluster.lab.name} --project ${var.project_id} --zone ${var.zone} --internal-ip"
}
