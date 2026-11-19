ALTER TABLE clusters
    ADD COLUMN cluster_capabilities jsonb,
    ADD CONSTRAINT clusters_capabilities_object
        CHECK (cluster_capabilities IS NULL OR jsonb_typeof(cluster_capabilities) = 'object');
