package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/auditchain"
	"kordex.local/control-plane/internal/config"
	"kordex.local/control-plane/internal/store"
)

const (
	maxRecords = 100_000
	maxNDJSON  = 16 << 20
	maxBundle  = 128 << 20
)

type bundle = auditchain.ExportBundle

func main() {
	output := flag.String("output", "", "new JSON bundle path; existing files are never replaced")
	flag.Parse()
	if flag.NArg() != 0 || *output == "" {
		fatal(errors.New("usage: kordex-security-audit-export -output NEW_FILE.json (DATABASE_URL must be set)"))
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fatal(errors.New("DATABASE_URL is required"))
	}
	if err := config.ValidateDatabaseURL(dsn, os.Getenv("KORDEX_LOCAL_DEVELOPMENT") == "true"); err != nil {
		fatal(err)
	}
	key, err := loadAuditSigningKey(os.Getenv("KORDEX_AUDIT_SIGNING_KEY_FILE"))
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		fatal(fmt.Errorf("open database: %w", err))
	}
	defer db.Close()
	if err = db.Ready(ctx); err != nil {
		fatal(fmt.Errorf("database migrations are not ready: %w", err))
	}
	data, eventCount, throughID, err := createBundle(ctx, db, key)
	if err != nil {
		fatal(err)
	}
	if err = writeNewFile(*output, data); err != nil {
		fatal(err)
	}
	digest := sha256.Sum256(data)
	fmt.Printf("Security audit bundle written: %s\nthrough_event_id=%d\nrecord_count=%d\nsha256=%s\n", *output, throughID, eventCount, hex.EncodeToString(digest[:]))
}

type auditSource interface {
	SecurityAuditCheckpoint(context.Context) (int64, []byte, error)
	ListSecurityAudit(context.Context, int64, int64, int) ([]auditchain.Record, error)
}

func createBundle(ctx context.Context, db auditSource, private ed25519.PrivateKey) ([]byte, int, int64, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, 0, 0, errors.New("audit signing key is unavailable")
	}
	throughID, expectedHead, err := db.SecurityAuditCheckpoint(ctx)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read security audit checkpoint: %w", err)
	}
	if throughID < 1 {
		return nil, 0, 0, errors.New("security audit stream is empty")
	}
	var records []byte
	var count int
	var afterID int64
	previous := make([]byte, sha256.Size)
	for afterID < throughID {
		page, pageErr := db.ListSecurityAudit(ctx, afterID, throughID, 1000)
		if pageErr != nil {
			return nil, 0, 0, fmt.Errorf("read security audit page: %w", pageErr)
		}
		if len(page) == 0 {
			return nil, 0, 0, fmt.Errorf("security audit page ended before checkpoint %d", throughID)
		}
		for _, record := range page {
			if record.OrganizationID != "kordex-security" || record.Action != "authorization.denied" || record.ID <= afterID {
				return nil, 0, 0, errors.New("security audit page has invalid scope or ordering")
			}
			verified, verifyErr := auditchain.Verify(record, previous)
			if verifyErr != nil {
				return nil, 0, 0, fmt.Errorf("verify security audit event %d: %w", record.ID, verifyErr)
			}
			previous = verified
			line, marshalErr := json.Marshal(record)
			if marshalErr != nil {
				return nil, 0, 0, marshalErr
			}
			if len(records)+len(line)+1 > maxNDJSON || count >= maxRecords {
				return nil, 0, 0, errors.New("security audit export exceeds the 100000-record or 16 MiB NDJSON limit")
			}
			records = append(records, line...)
			records = append(records, '\n')
			count++
			afterID = record.ID
		}
	}
	if afterID != throughID || count == 0 {
		return nil, 0, 0, errors.New("security audit export did not reach its fixed checkpoint")
	}
	if len(previous) != len(expectedHead) || subtle.ConstantTimeCompare(previous, expectedHead) != 1 {
		return nil, 0, 0, errors.New("security audit records do not match the captured chain checkpoint")
	}
	recordsHash := sha256.Sum256(records)
	manifest := bundle{
		Format: "kordex-audit-export-v1", RecordsFormat: "ndjson-v1", OrganizationID: "kordex-security",
		ThroughEventID: throughID, RecordCount: count, RecordsSHA256: hex.EncodeToString(recordsHash[:]),
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), RecordsNDJSON: string(records),
	}
	public := private.Public().(ed25519.PublicKey)
	if err = auditchain.SignExportBundle(&manifest, protocol.KeyID(public), private); err != nil {
		return nil, 0, 0, fmt.Errorf("sign security audit export: %w", err)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(data) > maxBundle {
		return nil, 0, 0, errors.New("security audit JSON bundle exceeds the 128 MiB verifier limit")
	}
	return data, count, throughID, nil
}

func loadAuditSigningKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("KORDEX_AUDIT_SIGNING_KEY_FILE is required")
	}
	return auditchain.LoadPrivateKeyFile(path)
}
func writeNewFile(path string, data []byte) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(absolute)
	temporary := filepath.Join(directory, ".kordex-security-audit-"+store.NewID()+".tmp")
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary export: %w", err)
	}
	defer os.Remove(temporary)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write temporary export: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close temporary export: %w", closeErr)
	}
	if err = os.Link(temporary, absolute); err != nil {
		return fmt.Errorf("publish export without replacing an existing file: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open export directory for sync: %w", err)
	}
	syncErr := dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil {
		return fmt.Errorf("sync export directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close export directory: %w", closeErr)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "security audit export failed:", err)
	os.Exit(1)
}
