-- Authenticated authorization denials are platform security events, not entries
-- in the target organization's audit chain. The chain head serializes appends.
CREATE TABLE security_audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid,
    actor text NOT NULL CHECK (length(actor) BETWEEN 1 AND 512),
    reason text NOT NULL CHECK (reason IN ('membership_denied','role_denied')),
    route text NOT NULL CHECK (length(route) BETWEEN 1 AND 512),
    method text NOT NULL CHECK (method IN ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')),
    role text NOT NULL DEFAULT '' CHECK (length(role) <= 64),
    request_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    previous_hash bytea NOT NULL CHECK (octet_length(previous_hash)=32),
    event_hash bytea NOT NULL CHECK (octet_length(event_hash)=32)
);
CREATE INDEX security_audit_events_time ON security_audit_events (occurred_at,id);

CREATE TABLE security_audit_chain_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_event_id bigint NOT NULL DEFAULT 0 CHECK (last_event_id >= 0),
    last_hash bytea NOT NULL DEFAULT decode(repeat('00',32),'hex') CHECK (octet_length(last_hash)=32)
);
INSERT INTO security_audit_chain_head(singleton) VALUES (true);

CREATE FUNCTION reject_security_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'security_audit_events is append only' USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER security_audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON security_audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_security_audit_mutation();
CREATE TRIGGER security_audit_events_no_truncate
    BEFORE TRUNCATE ON security_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_security_audit_mutation();
REVOKE UPDATE, DELETE, TRUNCATE ON security_audit_events FROM PUBLIC;
