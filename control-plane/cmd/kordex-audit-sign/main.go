package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/auditchain"
)

const (
	maxRecords = 100_000
	maxExport  = 64 << 20
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "audit checkpoint signing failed:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("kordex-audit-sign", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	inputPath := flags.String("input", "", "tenant audit NDJSON export")
	organization := flags.String("organization-id", "", "expected organization UUID")
	throughID := flags.Int64("through-id", 0, "fixed final audit event ID")
	outputPath := flags.String("output", "", "new signed checkpoint JSON file; never overwritten")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errors.New("invalid audit checkpoint arguments")
	}
	if flags.NArg() != 0 || *inputPath == "" || *outputPath == "" || !protocol.ValidUUID(*organization) || *throughID < 1 {
		return errors.New("usage: kordex-audit-sign -input export.jsonl -organization-id UUID -through-id ID -output NEW_CHECKPOINT.json (KORDEX_AUDIT_SIGNING_KEY_FILE must be set)")
	}
	private, err := auditchain.LoadPrivateKeyFile(os.Getenv("KORDEX_AUDIT_SIGNING_KEY_FILE"))
	if err != nil {
		return err
	}
	data, recordCount, err := readAndVerifyExport(*inputPath, *organization, *throughID)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	checkpoint := auditchain.ExportCheckpoint{
		Format: "kordex-audit-checkpoint-v1", OrganizationID: *organization,
		ThroughEventID: *throughID, RecordCount: recordCount,
		RecordsSHA256: hex.EncodeToString(digest[:]), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	public := private.Public().(ed25519.PublicKey)
	if err = auditchain.SignExportCheckpoint(&checkpoint, protocol.KeyID(public), private); err != nil {
		return fmt.Errorf("sign tenant audit checkpoint: %w", err)
	}
	manifest, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return err
	}
	manifest = append(manifest, '\n')
	if err = writeNewFile(*outputPath, manifest); err != nil {
		return err
	}
	fmt.Printf("Signed audit checkpoint written: %s\norganization_id=%s\nthrough_event_id=%d\nrecord_count=%d\nsha256=%s\nkey_id=%s\n", *outputPath, checkpoint.OrganizationID, checkpoint.ThroughEventID, checkpoint.RecordCount, checkpoint.RecordsSHA256, checkpoint.SigningKeyID)
	return nil
}

func readAndVerifyExport(path, organization string, throughID int64) ([]byte, int, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maxExport {
		return nil, 0, errors.New("audit export must be a regular file no larger than 64 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, errors.New("open audit export failed")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, 0, errors.New("audit export changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxExport+1))
	if err != nil || len(data) > maxExport {
		return nil, 0, errors.New("read audit export failed or exceeded 64 MiB")
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, 0, errors.New("audit export must be newline-terminated NDJSON")
	}
	count, _, err := auditchain.VerifyExportRecords(data, organization, throughID, true)
	if err != nil {
		return nil, 0, err
	}
	return data, count, nil
}

func writeNewFile(path string, data []byte) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(abs)
	randomSuffix := make([]byte, 8)
	if _, err = rand.Read(randomSuffix); err != nil {
		return fmt.Errorf("generate temporary checkpoint name: %w", err)
	}
	temporary := filepath.Join(directory, ".kordex-audit-checkpoint-"+hex.EncodeToString(randomSuffix)+".tmp")
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary checkpoint: %w", err)
	}
	defer os.Remove(temporary)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write temporary checkpoint: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close temporary checkpoint: %w", closeErr)
	}
	if err = os.Link(temporary, abs); err != nil {
		return fmt.Errorf("publish checkpoint without replacing an existing file: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open checkpoint directory for sync: %w", err)
	}
	syncErr := dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil {
		return fmt.Errorf("sync checkpoint directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close checkpoint directory: %w", closeErr)
	}
	return nil
}
