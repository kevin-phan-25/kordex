// kordex-trust-export derives the public operator trust bundle from an
// existing maintenance signing key. It never creates or prints key material.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"kordex.local/api/protocol"
)

const maxPrivateKeyFileSize = 256

func main() {
	privatePath := flag.String("private-file", "", "existing maintenance signing key file")
	publicPath := flag.String("public-file", "", "new public trust bundle path; never overwritten")
	flag.Parse()
	if *privatePath == "" || *publicPath == "" {
		fmt.Fprintln(os.Stderr, "private-file and public-file are required")
		os.Exit(2)
	}
	if err := exportBundle(*privatePath, *publicPath); err != nil {
		fmt.Fprintln(os.Stderr, "could not export maintenance public trust bundle:", err)
		os.Exit(1)
	}
	fmt.Println("Wrote public trust bundle; private signing material was not exported.")
}

func exportBundle(privatePath, publicPath string) error {
	privateAbs, err := filepath.Abs(privatePath)
	if err != nil {
		return errors.New("invalid private key path")
	}
	publicAbs, err := filepath.Abs(publicPath)
	if err != nil {
		return errors.New("invalid public bundle path")
	}
	if filepath.Clean(privateAbs) == filepath.Clean(publicAbs) {
		return errors.New("private key and public bundle paths must differ")
	}

	private, err := readExistingPrivateKey(privateAbs)
	if err != nil {
		return err
	}
	public := private.Public().(ed25519.PublicKey)
	bundle, err := json.MarshalIndent(map[string]string{
		protocol.KeyID(public): protocol.EncodeKey(public),
	}, "", "  ")
	if err != nil {
		return errors.New("encode public trust bundle")
	}
	bundle = append(bundle, '\n')

	file, err := os.OpenFile(publicAbs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return errors.New("create public bundle failed; output must be a new file")
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(publicAbs)
		}
	}()
	if _, err = file.Write(bundle); err != nil {
		return errors.New("write public trust bundle failed")
	}
	if err = file.Sync(); err != nil {
		return errors.New("sync public trust bundle failed")
	}
	if err = file.Close(); err != nil {
		return errors.New("close public trust bundle failed")
	}
	keep = true
	return nil
}

func readExistingPrivateKey(path string) (ed25519.PrivateKey, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("existing maintenance key file is unavailable")
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("maintenance key must be a regular, non-symlink file")
	}
	mode := before.Mode().Perm()
	// Kubernetes projected Secret files may be group-readable by the configured
	// service group. Reject group/world write, world read, and all execute bits.
	if mode&0o022 != 0 || mode&0o005 != 0 || mode&0o111 != 0 {
		return nil, errors.New("maintenance key permissions are too broad")
	}
	if before.Size() <= 0 || before.Size() > maxPrivateKeyFileSize {
		return nil, errors.New("maintenance key file has an invalid size")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open existing maintenance key failed")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return nil, errors.New("maintenance key changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPrivateKeyFileSize+1))
	if err != nil || len(data) > maxPrivateKeyFileSize {
		return nil, errors.New("read existing maintenance key failed")
	}
	encoded := strings.TrimSpace(string(data))
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || base64.RawStdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("maintenance key encoding is invalid")
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !equalBytes(derived, raw) {
			return nil, errors.New("maintenance private key is not canonical")
		}
		return derived, nil
	default:
		return nil, errors.New("maintenance key has an invalid Ed25519 size")
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for i := range left {
		different |= left[i] ^ right[i]
	}
	return different == 0
}
