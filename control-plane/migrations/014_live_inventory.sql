ALTER TABLE clusters
    ADD COLUMN provider_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT clusters_provider_metadata_object
        CHECK (jsonb_typeof(provider_metadata) = 'object');

ALTER TABLE nodes
    ADD COLUMN first_seen_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_seen_at timestamptz,
    ADD COLUMN present boolean NOT NULL DEFAULT true;

UPDATE nodes n
SET last_seen_at = coalesce(c.observed_at, n.first_seen_at)
FROM clusters c
WHERE c.id = n.cluster_id;

ALTER TABLE nodes ALTER COLUMN last_seen_at SET NOT NULL;
ALTER TABLE nodes ALTER COLUMN last_seen_at SET DEFAULT now();
ALTER TABLE nodes DROP CONSTRAINT nodes_cluster_id_name_key;
CREATE UNIQUE INDEX nodes_current_name ON nodes(cluster_id, name) WHERE present;
CREATE INDEX nodes_inventory_freshness ON nodes(cluster_id, present, last_seen_at);
