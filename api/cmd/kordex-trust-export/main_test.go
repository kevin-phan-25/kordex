package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"kordex.local/api/protocol"
)

func TestExportBundleDerivesMatchingPublicKeyWithoutChangingPrivateFile(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "maintenance.seed")
	publicPath := filepath.Join(directory, "keys.json")
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	privateBytes := []byte(base64.RawStdEncoding.EncodeToString(seed) + "\n")
	if err := os.WriteFile(privatePath, privateBytes, 0600); err != nil {
		t.Fatal(err)
	}

	if err := exportBundle(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	gotPrivate, err := os.ReadFile(privatePath)
	if err != nil || string(gotPrivate) != string(privateBytes) {
		t.Fatalf("existing private file changed: err=%v", err)
	}
	var got map[string]string
	data, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	if len(got) != 1 || got[protocol.KeyID(public)] != protocol.EncodeKey(public) {
		t.Fatalf("public trust bundle does not match existing key ID")
	}
}

func TestExportRejectsUnsafeOrInvalidInputs(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid.seed")
	if err := os.WriteFile(validPath, []byte(base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		prepare func(t *testing.T) (privatePath, publicPath string)
	}{
		{
			name:    "same path",
			prepare: func(t *testing.T) (string, string) { return validPath, validPath },
		},
		{
			name: "existing output",
			prepare: func(t *testing.T) (string, string) {
				out := filepath.Join(directory, "existing.json")
				if err := os.WriteFile(out, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
				return validPath, out
			},
		},
		{
			name: "broad permissions",
			prepare: func(t *testing.T) (string, string) {
				unsafe := filepath.Join(directory, "unsafe.seed")
				if err := os.WriteFile(unsafe, []byte(base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))), 0644); err != nil {
					t.Fatal(err)
				}
				return unsafe, filepath.Join(directory, "unsafe.json")
			},
		},
		{
			name: "invalid key encoding",
			prepare: func(t *testing.T) (string, string) {
				invalid := filepath.Join(directory, "invalid.seed")
				if err := os.WriteFile(invalid, []byte("not-a-key\n"), 0600); err != nil {
					t.Fatal(err)
				}
				return invalid, filepath.Join(directory, "invalid.json")
			},
		},
		{
			name: "symlink input",
			prepare: func(t *testing.T) (string, string) {
				link := filepath.Join(directory, "linked.seed")
				if err := os.Symlink(validPath, link); err != nil {
					t.Fatal(err)
				}
				return link, filepath.Join(directory, "linked.json")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privatePath, publicPath := tt.prepare(t)
			if err := exportBundle(privatePath, publicPath); err == nil {
				t.Fatal("unsafe input unexpectedly accepted")
			}
		})
	}
}
