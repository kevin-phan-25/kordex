package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/auditchain"
)

func main() {
	input := flag.String("input", "-", "ascending newline-delimited audit JSON records, or - for stdin")
	bundle := flag.Bool("bundle", false, "input is a kordex-audit-export-v1 JSON bundle")
	checkpointPath := flag.String("checkpoint", "", "signed kordex-audit-checkpoint-v1 manifest for the NDJSON input")
	throughID := flag.Int64("through-id", 0, "expected final audit event ID from the independently retained export manifest")
	trustBundle := flag.String("trust-bundle", "", "independently distributed JSON map of trusted audit signing key IDs to Ed25519 public keys")
	flag.Parse()
	if *throughID < 0 {
		fatal(errors.New("-through-id must be a positive event ID"))
	}
	var reader io.Reader = os.Stdin
	if *input != "-" {
		file, err := os.Open(*input)
		if err != nil {
			fatal(err)
		}
		defer file.Close()
		reader = file
	}
	var count int
	var chainedCount int
	var err error
	trustedKeys := map[string]ed25519.PublicKey(nil)
	if *trustBundle != "" {
		trustedKeys, err = loadTrustBundle(*trustBundle)
		if err != nil {
			fatal(err)
		}
	}
	if *bundle && *checkpointPath != "" || *checkpointPath != "" && *trustBundle == "" || *trustBundle != "" && !*bundle && *checkpointPath == "" {
		fatal(errors.New("-bundle and -checkpoint are mutually exclusive; signed verification requires -trust-bundle"))
	}
	if *bundle {
		count, err = verifyBundle(reader, *throughID, trustedKeys)
	} else if *checkpointPath != "" {
		count, chainedCount, err = verifyCheckpoint(reader, *checkpointPath, *throughID, trustedKeys)
	} else {
		count, err = verify(reader, *throughID)
	}
	if err != nil {
		fatal(err)
	}
	if *bundle && *throughID == 0 {
		fmt.Fprintln(os.Stderr, "note: using the bundle's self-reported checkpoint; supply -through-id from an independently retained manifest to detect a missing tail")
	}
	if *checkpointPath != "" && *throughID == 0 {
		fmt.Fprintln(os.Stderr, "note: the signed checkpoint authenticates this export; retain an independent high-water record to establish when the snapshot was taken")
	}
	if *checkpointPath != "" {
		if chainedCount == 0 {
			fmt.Printf("Verified %d audit records against the signed checkpoint; no hash-chained records were present.\n", count)
		} else {
			fmt.Printf("Verified %d audit records against the signed checkpoint; hash chain verified for %d records.\n", count, chainedCount)
		}
	} else {
		fmt.Printf("Verified %d hash-chained audit records; legacy unchained records were skipped.\n", count)
	}
}

func verify(input io.Reader, throughID int64) (int, error) {
	count, _, err := verifyRecords(input, throughID, "")
	return count, err
}

func verifyRecords(input io.Reader, throughID int64, expectedOrganization string) (int, int, error) {
	decoder := json.NewDecoder(bufio.NewReader(input))
	decoder.DisallowUnknownFields()
	previous := make([]byte, 32)
	organization := ""
	lastID := int64(0)
	lastHashedID := int64(0)
	count := 0
	recordCount := 0
	chainStarted := false
	for {
		var record auditchain.Record
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return count, recordCount, fmt.Errorf("decode audit record %d: %w", recordCount+1, err)
		}
		recordCount++
		if record.ID <= lastID {
			return count, recordCount, fmt.Errorf("audit records are not in ascending ID order at %d", record.ID)
		}
		lastID = record.ID
		if organization == "" {
			organization = record.OrganizationID
		} else if organization != record.OrganizationID {
			return count, recordCount, errors.New("input contains multiple organizations")
		}
		if expectedOrganization != "" && record.OrganizationID != expectedOrganization {
			return count, recordCount, errors.New("audit record organization does not match export bundle")
		}
		if record.EventHash == "" {
			if chainStarted || record.PreviousHash != "" {
				return count, recordCount, fmt.Errorf("incomplete hash chain at audit ID %d", record.ID)
			}
			continue
		}
		// Audit IDs share one PostgreSQL sequence across organizations, while
		// each organization's hash chain advances independently. Gaps are valid;
		// a missing same-organization row is detected by the next previous hash,
		// and a missing tail is detected by the independently retained checkpoint.
		if !chainStarted {
			previous = make([]byte, 32)
			chainStarted = true
		}
		actual, err := auditchain.Verify(record, previous)
		if err != nil {
			return count, recordCount, fmt.Errorf("verify audit ID %d: %w", record.ID, err)
		}
		previous = actual
		lastHashedID = record.ID
		count++
	}
	if count == 0 {
		return 0, recordCount, errors.New("input contains no verifiable hash-chained records")
	}
	if throughID > 0 && lastHashedID != throughID {
		return count, recordCount, fmt.Errorf("last chained event ID is %d; expected manifest checkpoint %d", lastHashedID, throughID)
	}
	return count, recordCount, nil
}

func verifyBundle(input io.Reader, externalThroughID int64, trustedKeys map[string]ed25519.PublicKey) (int, error) {
	const maxBundleBytes = 128 << 20
	data, err := io.ReadAll(io.LimitReader(input, maxBundleBytes+1))
	if err != nil {
		return 0, fmt.Errorf("read audit export bundle: %w", err)
	}
	if len(data) > maxBundleBytes {
		return 0, errors.New("audit export bundle exceeds the 128 MiB verifier limit")
	}
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return 0, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle auditchain.ExportBundle
	if err = decoder.Decode(&bundle); err != nil {
		return 0, fmt.Errorf("decode audit export bundle: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return 0, errors.New("audit export bundle has trailing JSON")
		}
		return 0, fmt.Errorf("decode trailing audit export bundle data: %w", err)
	}
	createdAt, timeErr := time.Parse(time.RFC3339Nano, bundle.CreatedAt)
	if bundle.Format != "kordex-audit-export-v1" || bundle.RecordsFormat != "ndjson-v1" || strings.TrimSpace(bundle.OrganizationID) == "" || bundle.ThroughEventID < 1 || bundle.RecordCount < 1 || len(bundle.RecordsSHA256) != sha256.Size*2 || timeErr != nil || createdAt.IsZero() {
		return 0, errors.New("audit export bundle manifest is invalid")
	}
	if (bundle.SigningKeyID == "") != (bundle.Signature == "") {
		return 0, errors.New("audit export bundle signature fields are incomplete")
	}
	if bundle.OrganizationID == "kordex-security" && bundle.Signature == "" {
		return 0, errors.New("platform security audit bundle must have a trusted signature")
	}
	if bundle.Signature != "" {
		public, ok := trustedKeys[bundle.SigningKeyID]
		if !ok {
			return 0, errors.New("audit export signing key is not present in the supplied trust bundle")
		}
		if !auditchain.VerifyExportBundleSignature(bundle, public) {
			return 0, errors.New("audit export bundle signature is invalid")
		}
	}
	claimedDigest, err := hex.DecodeString(bundle.RecordsSHA256)
	if err != nil {
		return 0, errors.New("audit export bundle SHA-256 is invalid")
	}
	records := []byte(bundle.RecordsNDJSON)
	actualDigest := sha256.Sum256(records)
	if subtle.ConstantTimeCompare(claimedDigest, actualDigest[:]) != 1 {
		return 0, errors.New("audit export bundle records SHA-256 mismatch")
	}
	if len(records) == 0 || records[len(records)-1] != '\n' {
		return 0, errors.New("audit export bundle records are not newline-terminated NDJSON")
	}
	if err := rejectDuplicateNDJSONMembers(records); err != nil {
		return 0, err
	}
	checkpoint := bundle.ThroughEventID
	if externalThroughID > 0 {
		if bundle.ThroughEventID != externalThroughID {
			return 0, fmt.Errorf("bundle checkpoint %d does not match independently retained checkpoint %d", bundle.ThroughEventID, externalThroughID)
		}
		checkpoint = externalThroughID
	}
	hashedCount, recordCount, err := verifyRecords(bytes.NewReader(records), checkpoint, bundle.OrganizationID)
	if err != nil {
		return hashedCount, err
	}
	if recordCount != bundle.RecordCount {
		return hashedCount, fmt.Errorf("bundle contains %d records; manifest says %d", recordCount, bundle.RecordCount)
	}
	return hashedCount, nil
}

func loadTrustBundle(path string) (map[string]ed25519.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > 64<<10 {
		return nil, errors.New("audit trust bundle must be a regular JSON file no larger than 64 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open audit trust bundle failed")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("audit trust bundle changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return nil, errors.New("read audit trust bundle failed or exceeded 64 KiB")
	}
	if err = rejectDuplicateJSONMembers(data); err != nil {
		return nil, fmt.Errorf("validate audit trust bundle: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	keys := map[string]string{}
	if err = decoder.Decode(&keys); err != nil || len(keys) == 0 || len(keys) > 32 {
		return nil, errors.New("audit trust bundle must contain between 1 and 32 key ID entries")
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("audit trust bundle has trailing JSON")
	}
	trusted := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, encoded := range keys {
		public, decodeErr := protocol.DecodeKey(encoded)
		if decodeErr != nil || protocol.KeyID(public) != keyID {
			return nil, fmt.Errorf("audit trust bundle contains an invalid public key entry %q", keyID)
		}
		trusted[keyID] = public
	}
	return trusted, nil
}

func verifyCheckpoint(input io.Reader, path string, externalThroughID int64, trustedKeys map[string]ed25519.PublicKey) (int, int, error) {
	const maxExportBytes = 64 << 20
	checkpointData, err := readRegularFile(path, 64<<10)
	if err != nil {
		return 0, 0, fmt.Errorf("read signed audit checkpoint: %w", err)
	}
	if err = rejectDuplicateJSONMembers(checkpointData); err != nil {
		return 0, 0, err
	}
	decoder := json.NewDecoder(bytes.NewReader(checkpointData))
	decoder.DisallowUnknownFields()
	var checkpoint auditchain.ExportCheckpoint
	if err = decoder.Decode(&checkpoint); err != nil {
		return 0, 0, fmt.Errorf("decode signed audit checkpoint: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return 0, 0, errors.New("signed audit checkpoint has trailing JSON")
	}
	createdAt, timeErr := time.Parse(time.RFC3339Nano, checkpoint.CreatedAt)
	if checkpoint.Format != "kordex-audit-checkpoint-v1" || !protocol.ValidUUID(checkpoint.OrganizationID) || checkpoint.ThroughEventID < 1 || checkpoint.RecordCount < 1 || checkpoint.RecordCount > 100_000 || len(checkpoint.RecordsSHA256) != sha256.Size*2 || timeErr != nil || createdAt.IsZero() {
		return 0, 0, errors.New("signed audit checkpoint manifest is invalid")
	}
	public, ok := trustedKeys[checkpoint.SigningKeyID]
	if !ok {
		return 0, 0, errors.New("audit checkpoint signing key is not present in the supplied trust bundle")
	}
	if !auditchain.VerifyExportCheckpointSignature(checkpoint, public) {
		return 0, 0, errors.New("audit checkpoint signature is invalid")
	}
	if externalThroughID > 0 && checkpoint.ThroughEventID != externalThroughID {
		return 0, 0, fmt.Errorf("signed checkpoint %d does not match independently retained checkpoint %d", checkpoint.ThroughEventID, externalThroughID)
	}
	records, err := readBounded(input, maxExportBytes)
	if err != nil {
		return 0, 0, err
	}
	claimedDigest, err := hex.DecodeString(checkpoint.RecordsSHA256)
	if err != nil {
		return 0, 0, errors.New("signed checkpoint SHA-256 is invalid")
	}
	actualDigest := sha256.Sum256(records)
	if subtle.ConstantTimeCompare(claimedDigest, actualDigest[:]) != 1 {
		return 0, 0, errors.New("signed checkpoint export SHA-256 mismatch")
	}
	recordCount, chainedCount, err := auditchain.VerifyExportRecords(records, checkpoint.OrganizationID, checkpoint.ThroughEventID, true)
	if err != nil {
		return recordCount, chainedCount, err
	}
	if recordCount != checkpoint.RecordCount {
		return recordCount, chainedCount, fmt.Errorf("signed export contains %d records; checkpoint says %d", recordCount, checkpoint.RecordCount)
	}
	return recordCount, chainedCount, nil
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, errors.New("input must be a regular file within its size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open input file failed")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("read input file failed or exceeded its size limit")
	}
	return data, nil
}

func readBounded(input io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read audit export: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, errors.New("audit export exceeds the 64 MiB verifier limit")
	}
	return data, nil
}

func rejectDuplicateJSONMembers(data []byte) error {
	if err := auditchain.RejectDuplicateJSONMembers(data); err != nil {
		return fmt.Errorf("validate audit export bundle JSON: %w", err)
	}
	return nil
}

func rejectDuplicateNDJSONMembers(data []byte) error {
	reader := bufio.NewReader(bytes.NewReader(data))
	lineNumber := 0
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNumber++
			line = bytes.TrimSuffix(line, []byte{'\n'})
			if len(bytes.TrimSpace(line)) == 0 {
				return fmt.Errorf("audit export bundle has an empty NDJSON record at line %d", lineNumber)
			}
			if err := rejectDuplicateJSONMembers(line); err != nil {
				return fmt.Errorf("audit export bundle record %d: %w", lineNumber, err)
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read audit export NDJSON: %w", err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "audit verification failed:", err)
	os.Exit(1)
}
