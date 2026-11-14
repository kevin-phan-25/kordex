package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"kordex.local/control-plane/migrations"
)

func migrationChecksum(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

// Migrate uses a transaction-scoped advisory lock, safe for competing runners.
// Migration 1 is immutable; new versions must extend this runner explicitly.
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(682491012)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	data, err := migrations.Files.ReadFile("001_foundation.sql")
	if err != nil {
		return err
	}
	checksum := migrationChecksum(data)
	var count int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		var actual string
		if err = tx.QueryRow(ctx, "SELECT checksum FROM schema_migrations WHERE version=1").Scan(&actual); err != nil {
			return fmt.Errorf("unsupported database schema: %w", err)
		}
		if count != 1 || actual != checksum {
			return fmt.Errorf("unsupported schema version or migration checksum mismatch")
		}
	} else {
		if _, err = tx.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("apply migration 1: %w", err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version,checksum) VALUES (1,$1)", checksum); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
