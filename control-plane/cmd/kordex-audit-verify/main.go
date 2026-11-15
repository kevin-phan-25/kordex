package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"kordex.local/control-plane/internal/auditchain"
)

func main() {
	input := flag.String("input", "-", "ascending newline-delimited audit JSON records, or - for stdin")
	throughID := flag.Int64("through-id", 0, "expected final audit event ID from the independently retained export manifest")
	flag.Parse()
	var reader io.Reader = os.Stdin
	if *input != "-" {
		file, err := os.Open(*input)
		if err != nil {
			fatal(err)
		}
		defer file.Close()
		reader = file
	}
	count, err := verify(reader, *throughID)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Verified %d hash-chained audit records; legacy unchained records were skipped.\n", count)
}

func verify(input io.Reader, throughID int64) (int, error) {
	decoder := json.NewDecoder(bufio.NewReader(input))
	previous := make([]byte, 32)
	organization := ""
	lastID := int64(0)
	lastHashedID := int64(0)
	count := 0
	chainStarted := false
	for {
		var record auditchain.Record
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return count, fmt.Errorf("decode audit record %d: %w", count+1, err)
		}
		if record.ID <= lastID {
			return count, fmt.Errorf("audit records are not in ascending ID order at %d", record.ID)
		}
		lastID = record.ID
		if organization == "" {
			organization = record.OrganizationID
		} else if organization != record.OrganizationID {
			return count, errors.New("input contains multiple organizations")
		}
		if record.EventHash == "" {
			if chainStarted || record.PreviousHash != "" {
				return count, fmt.Errorf("incomplete hash chain at audit ID %d", record.ID)
			}
			continue
		}
		if chainStarted && record.ID != lastHashedID+1 {
			return count, fmt.Errorf("audit chain has an event ID gap before %d", record.ID)
		}
		if !chainStarted {
			previous = make([]byte, 32)
			chainStarted = true
		}
		actual, err := auditchain.Verify(record, previous)
		if err != nil {
			return count, fmt.Errorf("verify audit ID %d: %w", record.ID, err)
		}
		previous = actual
		lastHashedID = record.ID
		count++
	}
	if count == 0 {
		return 0, errors.New("input contains no verifiable hash-chained records")
	}
	if throughID > 0 && lastHashedID != throughID {
		return count, fmt.Errorf("last chained event ID is %d; expected manifest checkpoint %d", lastHashedID, throughID)
	}
	return count, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "audit verification failed:", err)
	os.Exit(1)
}
