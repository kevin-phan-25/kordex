package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"kordex.local/control-plane/migrations"
)

type migration struct {
	version  int
	data     []byte
	checksum string
}

func migrationChecksum(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
func migrationPlan() ([]migration, error) {
	names, err := fs.Glob(migrations.Files, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	result := make([]migration, 0, len(names))
	for i, name := range names {
		prefix, _, ok := strings.Cut(name, "_")
		v, err := strconv.Atoi(prefix)
		if !ok || err != nil || v != i+1 {
			return nil, fmt.Errorf("migrations must be contiguous and ordered")
		}
		data, err := migrations.Files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		result = append(result, migration{v, data, migrationChecksum(data)})
	}
	return result, nil
}
func validateHistory(ctx context.Context, tx pgx.Tx, plan []migration) (int, error) {
	rows, err := tx.Query(ctx, "SELECT version,checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var version int
		var checksum string
		if err = rows.Scan(&version, &checksum); err != nil {
			return 0, err
		}
		if count >= len(plan) || version != plan[count].version || checksum != plan[count].checksum {
			return 0, fmt.Errorf("unknown schema version or migration checksum mismatch")
		}
		count++
	}
	return count, rows.Err()
}

// Migrate applies pending immutable migrations under one transaction and advisory lock.
func (s *Store) Migrate(ctx context.Context) error {
	plan, err := migrationPlan()
	if err != nil {
		return err
	}
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
	count, err := validateHistory(ctx, tx, plan)
	if err != nil {
		return err
	}
	for _, m := range plan[count:] {
		if _, err = tx.Exec(ctx, string(m.data)); err != nil {
			return fmt.Errorf("apply migration %d: %w", m.version, err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version,checksum) VALUES ($1,$2)", m.version, m.checksum); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) Ready(ctx context.Context) error {
	plan, err := migrationPlan()
	if err != nil {
		return err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	count, err := validateHistory(ctx, tx, plan)
	if err != nil {
		return err
	}
	if count != len(plan) {
		return fmt.Errorf("database migrations pending")
	}
	return tx.Commit(ctx)
}
