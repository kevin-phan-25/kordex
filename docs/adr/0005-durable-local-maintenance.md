# ADR 0005: signed local maintenance with retained coordination state

Status: accepted for constrained Phase 3 pilot, release 0.3.0.

A manual management-plane operation grants only ValidateOnly or DrainAndVerify against an immutable node and policy generation. Fifteen-minute hub-signed permits and a 45-second agent-published connectivity Lease fence new disruptive work. Trust roots are provisioned separately from the transport; stale/unknown evidence blocks. The operator reads live safety evidence and owns all Kubernetes side effects. No host package/reboot execution is introduced.

Use a NodeMaintenance CR as the durable delivery inbox and status checkpoint. Attach the recovery finalizer at agent creation. Persist terminal status until the hub acknowledges its sequence. Retain immutable operation receipts and a non-expiring cluster slot in a dedicated fixed namespace, independent of request/namespace/release lifetime. No process timeout or delivery lease may free capacity for a potentially disrupted node.

Persist cordon/eviction intent before side effects; constrain node patches by UID/resource version and eviction by pod UID. PDB failures never fall back to DELETE. Observe recovery after ambiguous responses. Recovery is narrowly authorized to verify and restore an owned cordon offline; new evictions always require fresh central evidence.

First-release safety is deliberately limited to healthy, opted-in stateless workers with Deployment/PDB protection. Persistent storage and control-plane nodes fail closed until reviewed adapters exist. MaintenanceCampaign's schema is reserved and explicitly reports orchestration unavailable. Full campaigns and fleet/site/organization concurrency remain Phase 4.

Runtime Secret data and Lease spec fields must not be managed as Helm snapshots. Preserve dynamic state on upgrades. The API group operations.kordex.local is a private pilot identifier; public domain ownership and conversion policy must be resolved before external API publication. These choices prioritize auditable recovery over automatic availability restoration under uncertainty.
