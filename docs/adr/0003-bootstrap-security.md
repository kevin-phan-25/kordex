# ADR 0003: constrained bootstrap authentication

Status: accepted for isolated foundation only.

Phase 1 needs authenticated API testing before OIDC/user memberships exist. Accept a generated bearer credential from the runtime environment and label audit attribution bootstrap-admin. Default to loopback, require database certificate verification outside explicit local-development mode, and document that all tenant access is globally administrative. This is a deliberate limited development surface, not production RBAC. Public deployment is blocked until OIDC and organization authorization are implemented. Never issue host or Kubernetes credentials through this surface.
