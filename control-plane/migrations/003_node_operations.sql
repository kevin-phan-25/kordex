ALTER TABLE clusters ADD CONSTRAINT clusters_org_id_unique UNIQUE(organization_id,id);
CREATE TABLE node_operations (
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES organizations(id),
 cluster_id uuid NOT NULL,
 request jsonb NOT NULL,
 command jsonb NOT NULL,
 phase text NOT NULL DEFAULT 'Pending',
 sequence bigint NOT NULL DEFAULT 0,
 status jsonb NOT NULL DEFAULT '{}'::jsonb,
 expires_at timestamptz NOT NULL,
 delivered_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY (organization_id,cluster_id) REFERENCES clusters(organization_id,id)
);
-- Phase 3 deliberately admits one manually requested operation per cluster.
-- Delivery/lease expiry never releases a potentially disrupted node.
CREATE UNIQUE INDEX node_operations_one_active ON node_operations(cluster_id)
 WHERE phase NOT IN ('Succeeded','Failed','Cancelled');
CREATE INDEX node_operations_inventory ON node_operations(organization_id,cluster_id,created_at,id);
