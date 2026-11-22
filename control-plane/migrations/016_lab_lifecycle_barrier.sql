-- The lab power lifecycle shares the clusters row lock with maintenance admission.
-- No row means legacy RUNNING until an operator explicitly requests a stop.
CREATE TABLE lab_lifecycle (
    cluster_id uuid PRIMARY KEY REFERENCES clusters(id),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    state text NOT NULL CHECK (state IN ('RUNNING','DRAINING','READY_TO_STOP','STOPPING','STOPPED','STARTING')),
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    reason text NOT NULL DEFAULT '',
    FOREIGN KEY (organization_id, cluster_id) REFERENCES clusters(organization_id,id)
);
