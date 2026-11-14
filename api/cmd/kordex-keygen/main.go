// kordex-keygen creates a new hub signing key and a matching operator trust bundle.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"kordex.local/api/protocol"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	privatePath := flag.String("private-file", "", "new private seed file (0600); never overwritten")
	publicPath := flag.String("public-file", "", "new JSON public trust bundle; never overwritten")
	flag.Parse()
	if *privatePath == "" || *publicPath == "" {
		return fmt.Errorf("private-file and public-file required")
	}
	a, err := filepath.Abs(*privatePath)
	if err != nil {
		return err
	}
	b, err := filepath.Abs(*publicPath)
	if err != nil {
		return err
	}
	if a == b {
		return fmt.Errorf("key paths must differ")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	bundle, err := json.MarshalIndent(map[string]string{protocol.KeyID(public): protocol.EncodeKey(public)}, "", "  ")
	if err != nil {
		return err
	}
	if err = writeNew(a, []byte(base64.RawStdEncoding.EncodeToString(private.Seed())+"\n"), 0600); err != nil {
		return err
	}
	if err = writeNew(b, append(bundle, '\n'), 0644); err != nil {
		return fmt.Errorf("private key was created; public bundle creation failed: %w", err)
	}
	fmt.Println("Created signing key and public trust bundle; key ID:", protocol.KeyID(public))
	return nil
}
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
