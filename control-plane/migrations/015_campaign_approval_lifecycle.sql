-- Existing approvals receive no grandfathered authorization window. Setting
-- their expiry to their creation time makes every legacy decision expired;
-- campaigns must obtain a fresh approval before admitting more work.
ALTER TABLE campaign_approvals ADD COLUMN expires_at timestamptz;
UPDATE campaign_approvals SET expires_at=created_at;
ALTER TABLE campaign_approvals ALTER COLUMN expires_at SET NOT NULL;
-- Keep older API replicas that omit expires_at from creating unbounded grants
-- during a coordinated rollout. Old scheduler replicas must still be stopped
-- before applying this migration because their admission query ignores expiry.
ALTER TABLE campaign_approvals ALTER COLUMN expires_at SET DEFAULT (clock_timestamp() + interval '24 hours');
ALTER TABLE campaign_approvals ADD COLUMN revoked_at timestamptz;
ALTER TABLE campaign_approvals ADD COLUMN revoked_by text;
ALTER TABLE campaign_approvals ADD COLUMN revocation_reason text;
ALTER TABLE campaign_approvals ADD CONSTRAINT campaign_approval_revocation_fields_check
 CHECK ((revoked_at IS NULL AND revoked_by IS NULL AND revocation_reason IS NULL)
     OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revocation_reason IS NOT NULL));

-- Once a campaign approval expires or is revoked, require an explicit fresh
-- approval for each remaining stage, even for a BeforeStart campaign.
ALTER TABLE campaigns ADD COLUMN approval_revalidation_required boolean NOT NULL DEFAULT false;
