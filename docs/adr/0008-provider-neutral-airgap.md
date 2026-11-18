# ADR 0008: Provider-neutral core and offline release bundles

Status: accepted.

## Context

Kordex must run in self-managed clusters, private data centers, edge sites, and
air-gapped networks. Requiring a cloud control API or public image registry at
runtime would exclude these environments and make the local safety model
dependent on external services.

## Decision

The control plane, agent, operator, campaigns, local Kubernetes safety,
PostgreSQL integration, and fixed-catalog Ansible EE remain provider-neutral.
Clusters initiate outbound management connections. GKE/EKS/AKS integrations
are optional adapters and cannot be prerequisites for core operation.

Release delivery uses OCI image archives, Helm packages, Kustomize manifests
and CRDs, a signed checksum manifest, and internal-registry mirroring. Build
base images must be supplied by digest for release bundle generation. Provider
credentials and signing private keys are excluded from bundles. The local
Kustomize overlay is self-managed by default and leaves upgrade gates disabled.

## Consequences

Disconnected installations can transfer reviewed artifacts and mirror them to
a registry reachable by cluster nodes. Release signing can run offline with
Ed25519 keys. Organizations remain responsible for trusted key distribution,
registry security, TLS, identity services, PostgreSQL operations, and backing
up trust material. This ADR establishes packaging and architecture support; it
does not claim that the host-upgrade executor has completed its VM failure
qualification.

## Rejected alternatives

- Making a cloud provider API the normal upgrade executor would make cloud
  identity and network access part of the safety-critical core.
- Relying on public registry pulls at runtime would break air-gapped installs.
- Treating a checksum file as a publisher signature would not authenticate the
  bundle, so signed releases use a detached Ed25519 signature.
