// Package auditchain provides the versioned hash format used for exported audit events.
package auditchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const Version = 1

var ErrInvalidRecord = errors.New("invalid audit chain record")

type Event struct {
	ID             int64           `json:"id"`
	OrganizationID string          `json:"organizationId"`
	Actor          string          `json:"actor"`
	Action         string          `json:"action"`
	ResourceID     string          `json:"resourceId"`
	RequestID      string          `json:"requestId"`
	OccurredAt     time.Time       `json:"occurredAt"`
	Metadata       json.RawMessage `json:"metadata"`
}

type Record struct {
	Event
	PreviousHash string `json:"previousHash"`
	EventHash    string `json:"eventHash"`
}

func Hash(previous []byte, event Event) ([]byte, error) {
	if len(previous) != sha256.Size || event.ID < 1 || event.OrganizationID == "" || !json.Valid(event.Metadata) {
		return nil, ErrInvalidRecord
	}
	event.OccurredAt = event.OccurredAt.UTC()
	payload, err := json.Marshal(struct {
		Version int `json:"version"`
		Event
	}{Version: Version, Event: event})
	if err != nil {
		return nil, err
	}
	input := make([]byte, 0, len(previous)+len(payload))
	input = append(input, previous...)
	input = append(input, payload...)
	value := sha256.Sum256(input)
	return value[:], nil
}

func Verify(record Record, previous []byte) ([]byte, error) {
	claimedPrevious, err := hex.DecodeString(record.PreviousHash)
	if err != nil || len(claimedPrevious) != sha256.Size || !equal(claimedPrevious, previous) {
		return nil, ErrInvalidRecord
	}
	claimedHash, err := hex.DecodeString(record.EventHash)
	if err != nil || len(claimedHash) != sha256.Size {
		return nil, ErrInvalidRecord
	}
	actual, err := Hash(previous, record.Event)
	if err != nil || !equal(actual, claimedHash) {
		return nil, ErrInvalidRecord
	}
	return actual, nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for i := range a {
		difference |= a[i] ^ b[i]
	}
	return difference == 0
}
