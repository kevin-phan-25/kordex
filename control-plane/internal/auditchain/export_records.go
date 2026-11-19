package auditchain

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// VerifyExportRecords checks an ordered, tenant-bound NDJSON snapshot and its
// hash chain. Legacy unchained records may form a prefix when allowLegacy is
// true; once a hash chain begins, every later record must remain in that chain.
func VerifyExportRecords(data []byte, organization string, throughID int64, allowLegacy bool) (recordCount, chainedCount int, err error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || organization == "" || throughID < 1 {
		return 0, 0, errors.New("audit export is empty, unterminated, or has an invalid checkpoint")
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	previous := make([]byte, sha256.Size)
	chainStarted := false
	lastID, lastHashedID := int64(0), int64(0)
	lineNumber := 0
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) != 0 {
			lineNumber++
			line = bytes.TrimSuffix(line, []byte{'\n'})
			if len(bytes.TrimSpace(line)) == 0 {
				return recordCount, chainedCount, fmt.Errorf("audit export has an empty record at line %d", lineNumber)
			}
			if lineNumber > 100_000 {
				return recordCount, chainedCount, errors.New("audit export exceeds the 100000-record limit")
			}
			if err = RejectDuplicateJSONMembers(line); err != nil {
				return recordCount, chainedCount, fmt.Errorf("audit record %d: %w", lineNumber, err)
			}
			decoder := json.NewDecoder(bytes.NewReader(line))
			decoder.DisallowUnknownFields()
			var record Record
			if err = decoder.Decode(&record); err != nil {
				return recordCount, chainedCount, fmt.Errorf("decode audit record %d: %w", lineNumber, err)
			}
			var trailing any
			if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				return recordCount, chainedCount, fmt.Errorf("audit record %d contains trailing JSON", lineNumber)
			}
			if record.ID <= lastID || record.OrganizationID != organization {
				return recordCount, chainedCount, errors.New("audit export organization or event ordering is invalid")
			}
			lastID = record.ID
			recordCount++
			if record.EventHash == "" {
				if chainStarted || record.PreviousHash != "" {
					return recordCount, chainedCount, fmt.Errorf("incomplete hash chain at audit ID %d", record.ID)
				}
			} else {
				actual, verifyErr := Verify(record, previous)
				if verifyErr != nil {
					return recordCount, chainedCount, fmt.Errorf("verify audit ID %d: %w", record.ID, verifyErr)
				}
				previous = actual
				chainStarted = true
				lastHashedID = record.ID
				chainedCount++
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return recordCount, chainedCount, fmt.Errorf("read audit export records: %w", readErr)
		}
	}
	if recordCount == 0 || lastID != throughID {
		return recordCount, chainedCount, errors.New("audit export does not end at the fixed event checkpoint")
	}
	if chainStarted && lastHashedID != throughID {
		return recordCount, chainedCount, errors.New("audit export hash chain does not reach the final event checkpoint")
	}
	if !chainStarted && !allowLegacy {
		return recordCount, chainedCount, errors.New("audit export contains no verifiable hash-chained records")
	}
	return recordCount, chainedCount, nil
}
