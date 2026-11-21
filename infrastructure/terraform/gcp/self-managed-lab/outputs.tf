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

output "k3s_system_images_manifest_version" {
  description = "Public manifest schema version used by the provisioned lab; consumed by guarded destroy only to evaluate the saved configuration."
  value       = var.k3s_system_images_manifest_version
}

output "k3s_system_images_k3s_version" {
  description = "Public K3s version bound by the verified system-image approval."
  value       = var.k3s_system_images_k3s_version
}

output "k3s_system_images_architecture" {
  description = "Public architecture bound by the verified system-image approval."
  value       = var.k3s_system_images_architecture
}

output "k3s_system_images_bundle_sha256" {
  description = "Public archive digest used by the provisioned lab."
  value       = var.k3s_system_images_bundle_sha256
}

output "k3s_system_images_bundle_mirror_url" {
  description = "Public approved archive URL used by the provisioned lab."
  value       = var.k3s_system_images_bundle_mirror_url
}

output "k3s_system_images_mirror_host" {
  description = "Public private-registry hostname used by the provisioned lab."
  value       = var.k3s_system_images_mirror_host
}

output "boot_image_id" {
  description = "Exact Ubuntu or Rocky Linux image selected during the Terraform plan; include it in qualification records."
  value       = local.boot_image
}

output "server_internal_ip" {
  description = "Private K3s server address; administer with IAP SSH and a local port-forward."
  value       = google_compute_instance.server.network_interface[0].network_ip
}

output "k3s_node_names" {
  description = "All K3s node names in control-plane, worker-1, worker-2 order."
  value = [
    google_compute_instance.server.name,
    google_compute_instance.worker["worker-1"].name,
    google_compute_instance.worker["worker-2"].name,
  ]
}

output "k3s_node_internal_ips" {
  description = "Private IP addresses corresponding to k3s_node_names."
  value = [
    google_compute_instance.server.network_interface[0].network_ip,
    google_compute_instance.worker["worker-1"].network_interface[0].network_ip,
    google_compute_instance.worker["worker-2"].network_interface[0].network_ip,
  ]
}

output "worker_names" {
  description = "Both Ubuntu workers. Each is the other's eligible worker peer for maintenance safety checks."
  value       = [for suffix in ["worker-1", "worker-2"] : google_compute_instance.worker[suffix].name]
}

output "worker_internal_ips" {
  description = "Private SSH addresses of both Ubuntu workers, reachable only inside the dedicated lab VPC."
  value       = [for suffix in ["worker-1", "worker-2"] : google_compute_instance.worker[suffix].network_interface[0].network_ip]
}

# Backwards-compatible aliases: worker-1 is the suggested first target; its
# peer is worker-2. Both names remain available in the plural outputs above.
output "worker_name" {
  description = "Backward-compatible alias for the first Ubuntu maintenance target."
  value       = google_compute_instance.worker["worker-1"].name
}

output "worker_internal_ip" {
  description = "Backward-compatible alias for the first Ubuntu maintenance target's private address."
  value       = google_compute_instance.worker["worker-1"].network_interface[0].network_ip
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
  value       = "Three private VMs (one K3s server and two Ubuntu workers), private DNS for restricted Google APIs, and destination-limited HTTPS egress are created. No VM external IPs or Cloud NAT exist. Run the guarded destroy helper after evidence export; the K3s join token is generated at runtime, expires in 30 minutes, is revoked after both workers join, and its Secret Manager secret expires after 4 hours."
}
