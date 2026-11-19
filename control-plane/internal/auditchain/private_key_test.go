package auditchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMountedPrivateKeyFileAllowsProjectedSecretModeOnly(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit-key")
	contents := []byte(base64.RawStdEncoding.EncodeToString(private.Seed()))
	if err = os.WriteFile(path, contents, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPrivateKeyFile(path); err == nil {
		t.Fatal("strict local key loader accepted group-readable key")
	}
	loaded, err := LoadMountedPrivateKeyFile(path)
	if err != nil || !loaded.Equal(private) {
		t.Fatalf("mounted key load equal=%v err=%v", err == nil && loaded.Equal(private), err)
	}
	if err = os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadMountedPrivateKeyFile(path); err == nil {
		t.Fatal("mounted key loader accepted world-readable key")
	}
}
