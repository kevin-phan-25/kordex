-- Audit chain heads serialize appends within an organization. Existing rows remain
-- explicitly unhashed; new events form a verifiable chain from the zero hash.
ALTER TABLE audit_events
    ADD COLUMN previous_hash bytea,
    ADD COLUMN event_hash bytea,
    ADD CONSTRAINT audit_previous_hash_size CHECK (previous_hash IS NULL OR octet_length(previous_hash)=32),
    ADD CONSTRAINT audit_event_hash_size CHECK (event_hash IS NULL OR octet_length(event_hash)=32);

CREATE TABLE audit_chain_heads (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id),
    last_event_id bigint NOT NULL DEFAULT 0 CHECK (last_event_id >= 0),
    last_hash bytea NOT NULL DEFAULT decode(repeat('00',32),'hex') CHECK (octet_length(last_hash)=32)
);
INSERT INTO audit_chain_heads(organization_id)
SELECT id FROM organizations ON CONFLICT DO NOTHING;

CREATE FUNCTION reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append only' USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC;
