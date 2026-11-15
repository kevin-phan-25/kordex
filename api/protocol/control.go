package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"
)

const CancellationAnnotation = OperationGroup + "/cancellation"

type OperationControl struct {
	OperationID   string    `json:"operationId"`
	ClusterID     string    `json:"clusterId"`
	CommandDigest string    `json:"commandDigest"`
	Kind          string    `json:"kind"`
	IssuedAt      time.Time `json:"issuedAt"`
	KeyID         string    `json:"keyId"`
	Signature     string    `json:"signature"`
}

func controlMessage(c OperationControl) ([]byte, error) {
	c.Signature = ""
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return append([]byte("kordex.control.v1\n"), data...), nil
}
func SignCancellation(operation, cluster, digest string, now time.Time, key ed25519.PrivateKey) (OperationControl, error) {
	if len(key) != ed25519.PrivateKeySize {
		return OperationControl{}, fmt.Errorf("invalid signing key")
	}
	c := OperationControl{OperationID: operation, ClusterID: cluster, CommandDigest: digest, Kind: "Cancel", IssuedAt: now, KeyID: KeyID(key.Public().(ed25519.PublicKey))}
	message, err := controlMessage(c)
	if err != nil {
		return c, err
	}
	c.Signature = Proof(key, message)
	return c, nil
}

// Cancellation cannot grant disruption. It remains valid for its exact immutable command until acknowledged.
func (c OperationControl) Verify(keys map[string]ed25519.PublicKey, operation, cluster, digest string, now time.Time) error {
	if c.Kind != "Cancel" || c.OperationID != operation || c.ClusterID != cluster || c.CommandDigest != digest || c.IssuedAt.IsZero() || c.IssuedAt.After(now.Add(5*time.Second)) {
		return fmt.Errorf("invalid operation control")
	}
	message, err := controlMessage(c)
	if err != nil {
		return err
	}
	key := keys[c.KeyID]
	if len(key) != ed25519.PublicKeySize || !VerifyProof(key, message, c.Signature) {
		return fmt.Errorf("invalid control signature")
	}
	return nil
}
