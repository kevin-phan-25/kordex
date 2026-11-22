output "project_id" {
  description = "GCP project ID recorded in this lab's Terraform state; the guarded helper checks this before destroy."
  value       = var.project_id
}

output "lab_id" {
  description = "Disposable lab identity (the Terraform name_prefix) used by guarded recovery commands."
  value       = var.name_prefix
}

output "zone" {
  description = "Zone recorded in this lab's Terraform state."
  value       = var.zone
}

output "server_name" {
  description = "K3s control-plane VM name."
  value       = google_compute_instance.server.name
}

output "os_family" {
  description = "Host catalog family configured for this lab."
  value       = var.os_family
}

output "qualification_os_profile" {
  description = "Exact supported OS profile bound into the reviewed Terraform plan."
  value       = var.qualification_os_profile
}

output "qualification_os_minor" {
  description = "Exact selected RHEL minor release, empty for Ubuntu/Debian."
  value       = var.qualification_os_minor
}

output "qualification_os_point_release" {
  description = "Exact Debian stable point or RHEL minor release bound to the approved package policy."
  value       = var.qualification_os_point_release
}

output "qualification_image_approval_reference" {
  description = "Customer image-owner approval record reference bound to the reviewed Terraform plan."
  value       = var.qualification_image_approval_reference
}

output "qualification_image_approval_sha256" {
  description = "Canonical digest of the image-owner approval record bound to the reviewed Terraform plan."
  value       = var.qualification_image_approval_sha256
}

output "qualification_image_unique_id" {
  description = "Google server-assigned numeric identity of the exact Debian/RHEL image checked against the owner approval record."
  value       = var.qualification_image_unique_id
}

output "boot_image_project" {
  description = "Image source project selected by the OS profile; RHEL uses the customer-approved exact image self-link."
  value       = var.qualification_os_profile == "debian-13" ? "debian-cloud" : var.qualification_os_profile == "ubuntu-24.04" ? "ubuntu-os-cloud" : split("/", var.rhel_image_self_link)[6]
}

output "boot_image_family" {
  description = "Exact resolved image name; Debian and RHEL are selected by exact approved self-link rather than a moving image family."
  value       = var.qualification_os_profile == "debian-13" ? basename(var.debian_image_self_link) : var.qualification_os_profile == "ubuntu-24.04" ? "ubuntu-2404-lts-amd64" : basename(var.rhel_image_self_link)
}

output "boot_architecture" {
  description = "The selected lab profile and K3s artifact lock are restricted to linux/amd64."
  value       = "linux/amd64"
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
  description = "Exact image selected during the Terraform plan; include it in qualification records."
  value       = local.boot_image
}

output "boot_image_unique_id" {
  description = "Google server-assigned identity of the exact boot image resolved by the reviewed Terraform plan."
  value = (
    var.qualification_os_profile == "debian-13" ? data.google_compute_image.debian_13[0].image_id :
    var.qualification_os_profile == "rhel-9" ? data.google_compute_image.rhel_9[0].image_id :
    data.google_compute_image.ubuntu_2404[0].image_id
  )
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
  description = "Both workers. Each is the other's eligible worker peer for maintenance safety checks."
  value       = [for suffix in ["worker-1", "worker-2"] : google_compute_instance.worker[suffix].name]
}

output "worker_internal_ips" {
  description = "Private SSH addresses of both selected-profile workers, reachable only inside the dedicated lab VPC."
  value       = [for suffix in ["worker-1", "worker-2"] : google_compute_instance.worker[suffix].network_interface[0].network_ip]
}

# Backwards-compatible aliases: worker-1 is the suggested first target; its
# peer is worker-2. Both names remain available in the plural outputs above.
output "worker_name" {
  description = "Backward-compatible alias for the first maintenance target."
  value       = google_compute_instance.worker["worker-1"].name
}

output "worker_internal_ip" {
  description = "Backward-compatible alias for the first maintenance target's private address."
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
  value       = "Three private VMs (one K3s server and two workers using the selected OS profile), private DNS for restricted Google APIs, and destination-limited HTTPS egress are created. No VM external IPs or Cloud NAT exist. Run the guarded destroy helper after evidence export; the K3s join token is generated at runtime, expires in 30 minutes, is revoked after both workers join, and its Secret Manager secret expires after 4 hours."
}
