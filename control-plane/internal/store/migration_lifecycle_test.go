package store

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestLegacyCampaignApprovalsExpireAtMigration(t *testing.T) {
	dsn := os.Getenv("KORDEX_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("database required")
		}
		t.Skip("disposable PostgreSQL database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("connect to disposable test database")
	}
	t.Cleanup(func() { admin.Close() })
	// Initialize the shared SECURITY DEFINER migration helper before applying
	// the historical schema in this isolated test namespace.
	if err = admin.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	schema := "approval_migration_" + strings.ReplaceAll(NewID(), "-", "")
	if _, err = admin.Pool.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Pool.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	legacy, err := Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	plan, err := migrationPlan()
	if err != nil || len(plan) < 15 || plan[14].version != 15 {
		t.Fatalf("expected migration 15 in plan for the legacy approval test: count=%d err=%v", len(plan), err)
	}
	tx, err := legacy.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE schema_migrations (version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	for _, item := range plan[:14] {
		if _, err = tx.Exec(ctx, string(item.data)); err != nil {
			tx.Rollback(ctx)
			t.Fatalf("apply historical migration %d: %v", item.version, err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version,checksum) VALUES ($1,$2)", item.version, item.checksum); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	orgID, campaignID, approvalID := NewID(), NewID(), NewID()
	created := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if _, err = legacy.Pool.Exec(ctx, "INSERT INTO organizations(id,name) VALUES ($1,$2)", orgID, "legacy-"+orgID); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Pool.Exec(ctx, "INSERT INTO campaigns(id,organization_id,spec,created_by) VALUES ($1,$2,'{}','legacy-user')", campaignID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Pool.Exec(ctx, `INSERT INTO campaign_approvals(id,campaign_id,plan_generation,stage,approval_epoch,snapshot_digest,actor,decision,created_at)
 VALUES ($1,$2,1,0,1,$3,'legacy-approver','Approved',$4)`, approvalID, campaignID, strings.Repeat("a", 64), created); err != nil {
		t.Fatal(err)
	}
	if err = legacy.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var expiresAt, createdAt time.Time
	var expired bool
	if err = legacy.Pool.QueryRow(ctx, "SELECT expires_at,created_at,expires_at<=clock_timestamp() FROM campaign_approvals WHERE id=$1", approvalID).Scan(&expiresAt, &createdAt, &expired); err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(createdAt) || !expired {
		t.Fatalf("legacy approval was not expired by migration: created=%s expires=%s expired=%v", createdAt, expiresAt, expired)
	}
	var compatibleCreatedAt, compatibleExpiresAt time.Time
	if err = legacy.Pool.QueryRow(ctx, `INSERT INTO campaign_approvals(id,campaign_id,plan_generation,stage,approval_epoch,snapshot_digest,actor,decision)
 VALUES ($1,$2,1,1,2,$3,'new-approver','Approved') RETURNING created_at,expires_at`, NewID(), campaignID, strings.Repeat("b", 64)).Scan(&compatibleCreatedAt, &compatibleExpiresAt); err != nil {
		t.Fatal("legacy API insert without expires_at was not kept bounded", err)
	}
	if lifetime := compatibleExpiresAt.Sub(compatibleCreatedAt); lifetime < 24*time.Hour-time.Second || lifetime > 24*time.Hour+time.Second {
		t.Fatalf("database compatibility default approval lifetime = %s, want 24h", lifetime)
	}
}
