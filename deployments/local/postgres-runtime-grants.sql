-- Apply as the migration owner after creating kordex_runtime and kordex_migrator.
-- The API/scheduler connect as kordex_runtime; only the pre-upgrade migration job
-- connects as kordex_migrator. Configure both credentials through the secret manager.
DO $$ BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO kordex_runtime', current_database());
END $$;
GRANT USAGE ON SCHEMA public TO kordex_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kordex_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kordex_runtime;

-- The app appends audit rows and reads them, but cannot rewrite or remove history.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM kordex_runtime;
GRANT SELECT, INSERT ON audit_events TO kordex_runtime;

-- Authenticated access denials use a separate platform-wide hash chain. Runtime
-- may append and export records but cannot rewrite or remove event rows.
REVOKE UPDATE, DELETE, TRUNCATE ON security_audit_events FROM kordex_runtime;
GRANT SELECT, INSERT ON security_audit_events TO kordex_runtime;
REVOKE INSERT, DELETE, TRUNCATE ON security_audit_chain_head FROM kordex_runtime;
GRANT SELECT, UPDATE ON security_audit_chain_head TO kordex_runtime;

-- API bearer-token revocations are append-only until their verified expiry.
-- The bounded SECURITY DEFINER function can remove only expired rows.
REVOKE UPDATE, DELETE, TRUNCATE ON oidc_token_revocations FROM kordex_runtime;
GRANT SELECT, INSERT ON oidc_token_revocations TO kordex_runtime;
GRANT EXECUTE ON FUNCTION purge_expired_oidc_token_revocations() TO kordex_runtime;

-- Readiness checks inspect migration versions; runtime cannot alter migration history.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON schema_migrations FROM kordex_runtime;
GRANT SELECT ON schema_migrations TO kordex_runtime;

-- Ensure future tables and sequences created by the migration owner receive the
-- same runtime grants. Reapply the audit_events/schema_migrations revocations after
-- each schema migration if new objects are introduced there.
ALTER DEFAULT PRIVILEGES FOR ROLE kordex_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kordex_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE kordex_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO kordex_runtime;
