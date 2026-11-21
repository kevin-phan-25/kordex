package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"kordex.local/api/artifactlock"
	"kordex.local/api/protocol"
)

func TestCheckExpectedInputsBindsTerraformValues(t *testing.T) {
	result := artifactlock.Verified{
		Lock:   artifactlock.Lock{MirrorReference: "https://mirror.customer.example/k3s"},
		Digest: "aabbcc",
	}
	if err := checkExpectedInputs(result, "aabbcc", result.Lock.MirrorReference); err != nil {
		t.Fatalf("matching Terraform values rejected: %v", err)
	}
	if err := checkExpectedInputs(result, "different", result.Lock.MirrorReference); err == nil {
		t.Fatal("Terraform digest mismatch accepted")
	}
	if err := checkExpectedInputs(result, result.Digest, "https://other.example/k3s"); err == nil {
		t.Fatal("Terraform mirror mismatch accepted")
	}
}

func TestReadPrivateSeedRequiresCanonicalPrivateFile(t *testing.T) {
	seed := sha256.Sum256([]byte("synthetic CLI test key only"))
	path := filepath.Join(t.TempDir(), "synthetic.seed")
	encoded := []byte(base64.RawStdEncoding.EncodeToString(seed[:]) + "\n")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateSeed(path); err != nil {
		t.Fatalf("valid synthetic seed rejected: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateSeed(path); err == nil {
		t.Fatal("group/world-readable private key accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.seed")
	if err := os.WriteFile(bad, []byte("not-base64!\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateSeed(bad); err == nil {
		t.Fatal("malformed key accepted")
	}
	symlink := filepath.Join(t.TempDir(), "seed-link")
	if err := os.Symlink(path, symlink); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := readPrivateSeed(symlink); err == nil {
		t.Fatal("private-key symlink accepted")
	}
}

func TestTrustExportWritesPublicOnlyAndPreservesRotation(t *testing.T) {
	seed := sha256.Sum256([]byte("synthetic existing artifact key; not production"))
	privatePath := filepath.Join(t.TempDir(), "existing.seed")
	if err := os.WriteFile(privatePath, []byte(base64.RawStdEncoding.EncodeToString(seed[:])+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	priorSeed := sha256.Sum256([]byte("synthetic previous rotation key"))
	prior := ed25519.NewKeyFromSeed(priorSeed[:])
	priorBundle, err := artifactlock.EncodeTrust(map[string]ed25519.PublicKey{protocol.KeyID(prior.Public().(ed25519.PublicKey)): prior.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	priorPath := filepath.Join(t.TempDir(), "prior.trust")
	if err := os.WriteFile(priorPath, priorBundle, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "new.trust")
	if err := run([]string{"trust-export", "--private-key-file", privatePath, "--prior-trust-bundle", priorPath, "--trust-out", output}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := artifactlock.ParseTrust(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected rotation overlap of two public keys, got %d", len(keys))
	}
	if _, err := os.Stat(privatePath); err != nil {
		t.Fatal("existing private seed was changed or removed")
	}
	if err := run([]string{"trust-export", "--private-key-file", privatePath, "--trust-out", output}); err == nil {
		t.Fatal("trust export overwrote existing bundle")
	}
}
