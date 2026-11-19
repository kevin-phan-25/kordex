-- Revoked API bearer tokens are stored by a one-way digest. A token remains
-- rejected until its already-verified issuer expiry; no raw credential is kept.
CREATE TABLE oidc_token_revocations (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL,
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    request_id uuid NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX oidc_token_revocations_expiry ON oidc_token_revocations (expires_at);

CREATE FUNCTION reject_oidc_token_revocation_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.expires_at <= clock_timestamp() THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'active OIDC token revocations are immutable' USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER oidc_token_revocations_no_update
    BEFORE UPDATE ON oidc_token_revocations
    FOR EACH ROW EXECUTE FUNCTION reject_oidc_token_revocation_mutation();
CREATE TRIGGER oidc_token_revocations_no_delete_active
    BEFORE DELETE ON oidc_token_revocations
    FOR EACH ROW EXECUTE FUNCTION reject_oidc_token_revocation_mutation();
CREATE TRIGGER oidc_token_revocations_no_truncate
    BEFORE TRUNCATE ON oidc_token_revocations
    FOR EACH STATEMENT EXECUTE FUNCTION reject_oidc_token_revocation_mutation();

-- Runtime may purge only entries that can no longer revoke a valid token.
CREATE FUNCTION purge_expired_oidc_token_revocations() RETURNS bigint
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    WITH removed AS (
        DELETE FROM public.oidc_token_revocations
        WHERE expires_at <= clock_timestamp()
        RETURNING 1
    )
    SELECT count(*)::bigint FROM removed;
$$;
REVOKE ALL ON FUNCTION purge_expired_oidc_token_revocations() FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON oidc_token_revocations FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_oidc_token_revocation_mutation() FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kordex_runtime') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON oidc_token_revocations FROM kordex_runtime;
        GRANT SELECT, INSERT ON oidc_token_revocations TO kordex_runtime;
        GRANT EXECUTE ON FUNCTION purge_expired_oidc_token_revocations() TO kordex_runtime;
    END IF;
END $$;
