// Package auditchain provides the versioned hash format used for exported audit events.
package auditchain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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

// ExportBundle is a portable high-water audit snapshot. Signature authenticates
// the manifest fields and records digest; verification still requires a public
// key obtained through an independent trust channel.
type ExportBundle struct {
	Format         string `json:"format"`
	RecordsFormat  string `json:"recordsFormat"`
	OrganizationID string `json:"organizationId"`
	ThroughEventID int64  `json:"throughEventId"`
	RecordCount    int    `json:"recordCount"`
	RecordsSHA256  string `json:"recordsSha256"`
	CreatedAt      string `json:"createdAt"`
	RecordsNDJSON  string `json:"recordsNdjson"`
	SigningKeyID   string `json:"signingKeyId,omitempty"`
	Signature      string `json:"signature,omitempty"`
}

// ExportCheckpoint signs a detached manifest for newline-delimited tenant audit
// exports. The file digest binds the exact exported bytes without embedding the
// potentially large records in the manifest.
type ExportCheckpoint struct {
	Format         string `json:"format"`
	OrganizationID string `json:"organizationId"`
	ThroughEventID int64  `json:"throughEventId"`
	RecordCount    int    `json:"recordCount"`
	RecordsSHA256  string `json:"recordsSha256"`
	CreatedAt      string `json:"createdAt"`
	SigningKeyID   string `json:"signingKeyId"`
	Signature      string `json:"signature"`
}

func ExportCheckpointSigningPayload(checkpoint ExportCheckpoint) ([]byte, error) {
	return json.Marshal(struct {
		Format         string `json:"format"`
		OrganizationID string `json:"organizationId"`
		ThroughEventID int64  `json:"throughEventId"`
		RecordCount    int    `json:"recordCount"`
		RecordsSHA256  string `json:"recordsSha256"`
		CreatedAt      string `json:"createdAt"`
		SigningKeyID   string `json:"signingKeyId"`
	}{checkpoint.Format, checkpoint.OrganizationID, checkpoint.ThroughEventID, checkpoint.RecordCount, checkpoint.RecordsSHA256, checkpoint.CreatedAt, checkpoint.SigningKeyID})
}

func SignExportCheckpoint(checkpoint *ExportCheckpoint, keyID string, private ed25519.PrivateKey) error {
	if checkpoint == nil || keyID == "" || len(private) != ed25519.PrivateKeySize {
		return ErrInvalidRecord
	}
	checkpoint.SigningKeyID = keyID
	payload, err := ExportCheckpointSigningPayload(*checkpoint)
	if err != nil {
		return err
	}
	checkpoint.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, payload))
	return nil
}

func VerifyExportCheckpointSignature(checkpoint ExportCheckpoint, public ed25519.PublicKey) bool {
	if len(public) != ed25519.PublicKeySize || checkpoint.SigningKeyID == "" || checkpoint.Signature == "" {
		return false
	}
	signature, err := base64.RawStdEncoding.DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	payload, err := ExportCheckpointSigningPayload(checkpoint)
	return err == nil && ed25519.Verify(public, payload, signature)
}

func ExportBundleSigningPayload(bundle ExportBundle) ([]byte, error) {
	return json.Marshal(struct {
		Format         string `json:"format"`
		RecordsFormat  string `json:"recordsFormat"`
		OrganizationID string `json:"organizationId"`
		ThroughEventID int64  `json:"throughEventId"`
		RecordCount    int    `json:"recordCount"`
		RecordsSHA256  string `json:"recordsSha256"`
		CreatedAt      string `json:"createdAt"`
		SigningKeyID   string `json:"signingKeyId"`
	}{bundle.Format, bundle.RecordsFormat, bundle.OrganizationID, bundle.ThroughEventID, bundle.RecordCount, bundle.RecordsSHA256, bundle.CreatedAt, bundle.SigningKeyID})
}

func SignExportBundle(bundle *ExportBundle, keyID string, private ed25519.PrivateKey) error {
	if bundle == nil || keyID == "" || len(private) != ed25519.PrivateKeySize {
		return ErrInvalidRecord
	}
	bundle.SigningKeyID = keyID
	payload, err := ExportBundleSigningPayload(*bundle)
	if err != nil {
		return err
	}
	bundle.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, payload))
	return nil
}

func VerifyExportBundleSignature(bundle ExportBundle, public ed25519.PublicKey) bool {
	if len(public) != ed25519.PublicKeySize || bundle.SigningKeyID == "" || bundle.Signature == "" {
		return false
	}
	signature, err := base64.RawStdEncoding.DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	payload, err := ExportBundleSigningPayload(bundle)
	return err == nil && ed25519.Verify(public, payload, signature)
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
