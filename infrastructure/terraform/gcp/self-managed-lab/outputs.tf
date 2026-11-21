output "project_id" {
  description = "GCP project ID recorded in this lab's Terraform state; the guarded helper checks this before destroy."
  value       = var.project_id
}

output "server_name" {
  description = "K3s control-plane VM name."
  value       = google_compute_instance.server.name
}

output "os_family" {
  description = "Host catalog family configured for this lab."
  value       = var.os_family
}

output "boot_image_id" {
  description = "Exact Ubuntu or Rocky Linux image selected during the Terraform plan; include it in qualification records."
  value       = local.boot_image
}

output "server_internal_ip" {
  description = "Private K3s server address; administer with IAP SSH and a local port-forward."
  value       = google_compute_instance.server.network_interface[0].network_ip
}

output "worker_name" {
  description = "Linux worker VM to use as the host-upgrade qualification target."
  value       = google_compute_instance.worker.name
}

output "worker_internal_ip" {
  description = "Private SSH address of the Linux worker, reachable only inside the dedicated lab VPC."
  value       = google_compute_instance.worker.network_interface[0].network_ip
}

output "agent_join_secret_name" {
  description = "Secret Manager metadata resource holding a runtime-created 30-minute K3s agent join token; payload is never in Terraform state."
  value       = google_secret_manager_secret.agent_join.secret_id
}

output "kubeconfig_read_command" {
  description = "Read the server kubeconfig over IAP; use only while the SSH tunnel is available and protect the local file."
  value       = "gcloud compute ssh ${google_compute_instance.server.name} --project=${var.project_id} --zone=${var.zone} --tunnel-through-iap --command='sudo cat /etc/rancher/k3s/k3s.yaml' > ./kubeconfig && chmod 600 ./kubeconfig"
}

output "iap_k3s_tunnel_command" {
  description = "Create an IAP-backed SSH tunnel for local kubectl access; run in a dedicated terminal."
  value       = "gcloud compute ssh ${google_compute_instance.server.name} --project=${var.project_id} --zone=${var.zone} --tunnel-through-iap -- -N -L 6443:127.0.0.1:6443"
}

output "cost_and_security_reminder" {
  description = "Reminder that this is a billable, disposable qualification environment."
  value       = "Two private VMs and temporary Cloud NAT are created. No VM external IPs exist. Run the guarded destroy helper after evidence export; the K3s join token is generated at runtime, expires in 30 minutes, is revoked after the worker joins, and its Secret Manager secret expires after 4 hours."
}
