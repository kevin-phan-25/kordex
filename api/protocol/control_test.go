package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignedWithdrawalBinding(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	roots := map[string]ed25519.PublicKey{KeyID(pub): pub}
	now := time.Now()
	id := "00000000-0000-4000-8000-000000000001"
	cluster := "00000000-0000-4000-8000-000000000002"
	c, e := SignCancellation(id, cluster, "digest", now, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Verify(roots, id, cluster, "digest", now.Add(24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if c.Verify(roots, id, cluster, "other", now) == nil {
		t.Fatal("wrong digest accepted")
	}
	c.Kind = "Proceed"
	if c.Verify(roots, id, cluster, "digest", now) == nil {
		t.Fatal("tampered control accepted")
	}
}
