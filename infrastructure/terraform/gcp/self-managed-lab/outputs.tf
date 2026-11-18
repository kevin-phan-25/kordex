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

output "server_external_ip" {
  description = "K3s API and SSH address, protected by the admin_cidr firewall rule."
  value       = google_compute_instance.server.network_interface[0].access_config[0].nat_ip
}

output "worker_name" {
  description = "Linux worker VM to use as the host-upgrade qualification target."
  value       = google_compute_instance.worker.name
}

output "worker_internal_ip" {
  description = "Private SSH address of the Linux worker, reachable from operator pods in this cluster."
  value       = google_compute_instance.worker.network_interface[0].network_ip
}

output "vm_service_account" {
  description = "Dedicated service account attached to both VMs; this module grants it no IAM roles."
  value       = google_service_account.lab.email
}

output "kubeconfig_copy_command" {
  description = "Copy the kubeconfig after the server startup script completes."
  value       = "gcloud compute scp ${var.ssh_user}@${google_compute_instance.server.name}:.kube/config ./kubeconfig --project=${var.project_id} --zone=${var.zone}"
}

output "cost_and_security_reminder" {
  description = "Reminder that this is a billable, disposable qualification environment."
  value       = "Two regular Linux VMs and external IPv4 addresses are created. Run terraform destroy after testing; Terraform state contains the K3s bootstrap token."
}
