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

func TestLoadMountedPrivateKeyFileResolvesKubeletProjectedSecretLayout(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mount := t.TempDir()
	version := filepath.Join(mount, "..2026_11_25_23_58_00.0000000000")
	if err = os.Mkdir(version, 0o755); err != nil {
		t.Fatal(err)
	}
	contents := []byte(base64.RawStdEncoding.EncodeToString(private.Seed()))
	if err = os.WriteFile(filepath.Join(version, "auditSigningKey"), contents, 0o440); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Base(version), filepath.Join(mount, "..data")); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(mount, "auditSigningKey")
	if err = os.Symlink("..data/auditSigningKey", keyPath); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadMountedPrivateKeyFile(keyPath)
	if err != nil || !loaded.Equal(private) {
		t.Fatalf("projected key load equal=%v err=%v", err == nil && loaded.Equal(private), err)
	}
}

func TestLoadMountedPrivateKeyFileRejectsProjectedSecretSymlinkEscape(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	mount := filepath.Join(parent, "mount")
	if err = os.Mkdir(mount, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err = os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	contents := []byte(base64.RawStdEncoding.EncodeToString(private.Seed()))
	if err = os.WriteFile(filepath.Join(outside, "auditSigningKey"), contents, 0o440); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("../outside", filepath.Join(mount, "..data")); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(mount, "auditSigningKey")
	if err = os.Symlink("..data/auditSigningKey", keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadMountedPrivateKeyFile(keyPath); err == nil {
		t.Fatal("projected Secret symlink escaping mount root was accepted")
	}
}

func TestLoadMountedPrivateKeyFileRejectsAbsoluteProjectedSecretSymlink(t *testing.T) {
	mount := t.TempDir()
	keyPath := filepath.Join(mount, "auditSigningKey")
	if err := os.Symlink("/etc/passwd", keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedPrivateKeyFile(keyPath); err == nil {
		t.Fatal("absolute projected Secret symlink was accepted")
	}
}
