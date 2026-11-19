-- Bind every active reservation to the target's observed topology zone.
-- Unknown historical zones remain the empty string and conservatively overlap
-- every zone during admission until their operation reaches a terminal phase.
ALTER TABLE operation_reservations
    ADD COLUMN zone_id text NOT NULL DEFAULT '';

UPDATE operation_reservations r
SET zone_id = COALESCE(
    NULLIF(n.inventory->>'zone', ''),
    NULLIF(n.inventory->'labels'->>'topology.kubernetes.io/zone', ''),
    NULLIF(n.inventory->'labels'->>'failure-domain.beta.kubernetes.io/zone', ''),
    ''
)
FROM nodes n
WHERE n.cluster_id = r.cluster_id AND n.uid = r.node_uid;

UPDATE operation_reservations
SET zone_id = ''
WHERE zone_id <> ''
  AND (char_length(zone_id) > 63 OR zone_id !~ '^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$');

ALTER TABLE operation_reservations
    ADD CONSTRAINT operation_reservations_zone_id_valid
    CHECK (zone_id = '' OR (char_length(zone_id) <= 63 AND zone_id ~ '^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$'));

CREATE INDEX reservation_active_zone
    ON operation_reservations (organization_id, zone_id)
    WHERE released_at IS NULL;

UPDATE organization_limits
SET limits = jsonb_set(limits, '{zone}', '1'::jsonb, true)
WHERE limits->'zone' IS NULL OR limits->'zone' = '0'::jsonb;

ALTER TABLE organization_limits
    ALTER COLUMN limits SET DEFAULT '{"organization":1,"fleet":1,"site":1,"zone":1,"cluster":1,"node":1,"maxUnavailablePerSite":1}'::jsonb;
