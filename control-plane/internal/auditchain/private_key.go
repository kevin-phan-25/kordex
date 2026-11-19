package auditchain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
)

// LoadPrivateKeyFile accepts the base64 Ed25519 seed format written by
// kordex-keygen and refuses symlinks and files readable by group or other.
func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	return loadPrivateKeyFile(path, false)
}

// LoadMountedPrivateKeyFile accepts a read-only Kubernetes projected Secret
// mode (0440) for a pod whose fsGroup is dedicated to that API workload. It
// still rejects world access, group write, symlinks, and non-regular files.
func LoadMountedPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	return loadPrivateKeyFile(path, true)
}

func loadPrivateKeyFile(path string, allowGroupRead bool) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("audit signing key file is required")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("audit signing key file must be a private regular file with mode 0600 or stricter")
	}
	perms := before.Mode().Perm()
	allowedMode := perms == 0o0400 || perms == 0o0600
	if allowGroupRead && perms == 0o0440 {
		allowedMode = true
	}
	if !before.Mode().IsRegular() || !allowedMode || before.Size() < 40 || before.Size() > 128 {
		return nil, errors.New("audit signing key file must be a private regular file with mode 0600 or stricter")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open audit signing key failed")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("audit signing key changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil || len(data) > 128 {
		return nil, errors.New("read audit signing key failed")
	}
	raw, err := base64.RawStdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil {
		return nil, errors.New("audit signing key encoding is invalid")
	}
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if len(raw) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize]), raw) {
		return ed25519.PrivateKey(raw), nil
	}
	return nil, errors.New("audit signing key must contain an Ed25519 seed or canonical private key")
}
