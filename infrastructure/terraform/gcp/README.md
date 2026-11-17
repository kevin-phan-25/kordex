# Optional GCP integration foundation

This module is intentionally opt-in and creates resources only in an existing, separately selected product project. It creates an Artifact Registry Docker repository and Secret Manager secret containers. It does not create or enable a GCP project, service account, secret payload, Cloud Run service, Cloud SQL instance, Pub/Sub topic, network, billing account, or IAM grants.

## Requirements

* Terraform 1.6 or later.
* A dedicated GCP project created and approved outside this module.
* The caller authenticated with Google Cloud ADC and already granted only the required Artifact Registry and Secret Manager permissions.
* Review and approve API enablement, cost, region, and retention requirements before applying.

## Plan and apply

```sh
cd infrastructure/terraform/gcp
cp terraform.tfvars.example terraform.tfvars
# Set the dedicated project ID, region, and globally unique repository/secret names.
terraform init
terraform plan -out=phase7.tfplan
terraform show phase7.tfplan
terraform apply phase7.tfplan
```

The module does not configure a remote Terraform backend. Before team use, provision an encrypted, access-controlled remote backend with state locking and recovery, and migrate state under an approved procedure. Do not commit `terraform.tfvars`, state, plan files, credentials, or secret values.

Destroying this module can delete registry images and secret containers. Review the plan and retention policy before any destroy. Enable APIs only when approved. Secret values are managed separately through Secret Manager and workload identity; Terraform never receives secret payloads.

Cloud Run, Cloud SQL, Pub/Sub, CI identity federation, private ingress, and production IAM are deliberately deferred until local and self-hosted deployment gates pass and cost/identity requirements are reviewed.

## Optional self-managed VM qualification lab

[`self-managed-lab/`](self-managed-lab/README.md) is a separate Terraform
module for creating a disposable two-node Ubuntu/K3s environment to exercise
the self-managed host executor. It uses GCP only to host the test VMs, requires
internet for first-boot downloads, and is not an air-gapped bootstrap test.
It does not install Kordex or enable its upgrade gates. Review the plan and
expected charges before applying it.
