# ADR 0001: modular hub and local safety authority

Status: accepted for foundation.

Use one modular control-plane service with PostgreSQL and separate logical agent/operator components. Outbound HTTPS avoids inbound customer API access. Local safety remains authoritative. This limits operational overhead while retaining a future leased scheduler and outbox boundary. Reject generic federation, Kafka, service mesh and provider-coupled core logic. Cost: agent identity and local durable execution need dedicated implementation and testing before operations are allowed.
