-- Keep per-campaign reconciliation independent of unrelated historical operations.
CREATE INDEX node_operations_campaign_progress ON node_operations(campaign_id,phase,terminal_at) WHERE campaign_id IS NOT NULL;
CREATE INDEX campaign_events_participants ON campaign_events(campaign_id,actor,kind);
CREATE INDEX clusters_site_health ON clusters(organization_id,site_id);
