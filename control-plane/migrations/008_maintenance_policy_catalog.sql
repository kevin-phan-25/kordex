ALTER TABLE clusters
    ADD COLUMN maintenance_policy_catalog jsonb,
    ADD COLUMN maintenance_policy_catalog_observed_at timestamptz,
    ADD CONSTRAINT clusters_policy_catalog_object
        CHECK (maintenance_policy_catalog IS NULL OR jsonb_typeof(maintenance_policy_catalog) = 'object');
