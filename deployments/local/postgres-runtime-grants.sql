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
