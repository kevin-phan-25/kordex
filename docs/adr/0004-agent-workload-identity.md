# ADR 0004: signed outbound HTTPS identity

Status: accepted for registration/inventory release 0.2.0.

Use per-cluster Ed25519 signatures over HTTPS as the workload identity model. This survives ordinary TLS-terminating ingress without trusting forwarded client-certificate headers and fits a future Cloud Run deployment. Bootstrap uses an administrator-issued 256-bit single-use token; private keys are generated and persisted in the managed cluster. Bind identity to the kube-system namespace UID and an administrator-created cluster UUID.

The database transaction fences identity changes and nonce reuse. Keys expire in 24 hours and rotate before twelve hours remain. The agent persists both current and pending keys before rotation so lost acknowledgements can be resolved by observation. Offline expiry and identity loss require explicit administrator recovery. HTTPS remains mandatory; application signatures do not encrypt enrollment tokens.

Human requests use OIDC with persistent organization membership. Bootstrap is disabled for non-loopback production ingress. No arbitrary remote shell or node maintenance capability is introduced. This release has no command queue because it accepts no execution commands.

Tradeoffs: custom canonical request signing requires focused interoperability/security tests, synchronized clocks and durable server-side replay storage. Kubernetes identity Secrets and Helm release storage are sensitive. One trusted OIDC issuer is configured; issuer changes require membership migration. A future externally managed workload identity or mTLS model can replace signing without coupling the inventory schema to a cloud provider.
