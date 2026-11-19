-- Supports organization-scoped recovery and failure review without scanning
-- the full operation history for each phase tab.
CREATE INDEX node_operations_org_phase_queue
    ON node_operations (organization_id, phase, created_at DESC, id DESC);
