output "artifact_registry_repository" {
  description = "Docker repository resource name."
  value       = google_artifact_registry_repository.images.name
}

output "artifact_registry_url" {
  description = "Docker image registry URL for the selected region and project."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_id}"
}

output "secret_names" {
  description = "Secret Manager containers. No secret payloads are created by this module."
  value       = { for key, value in google_secret_manager_secret.containers : key => value.name }
}
