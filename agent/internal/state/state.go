// Package state persists identity and sequence checkpoints before network side effects.
package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"kordex.local/api/protocol"
)

type State struct {
	ClusterID  string `json:"clusterId"`
	ClusterUID string `json:"clusterUid"`
	PrivateKey []byte `json:"privateKey"`
	PendingKey []byte `json:"pendingKey,omitempty"`
	Version    int64  `json:"version"`
	Revision   string `json:"-"`
}

func (s State) Validate() error {
	if len(s.PrivateKey) != 0 && !validPrivateKey(s.PrivateKey) {
		return fmt.Errorf("invalid stored private key")
	}
	if len(s.PendingKey) != 0 && !validPrivateKey(s.PendingKey) {
		return fmt.Errorf("invalid pending private key")
	}
	if s.Version < 0 {
		return fmt.Errorf("invalid inventory version")
	}
	if len(s.PrivateKey) == 0 {
		if s.ClusterID != "" || s.ClusterUID != "" || len(s.PendingKey) != 0 || s.Version != 0 {
			return fmt.Errorf("incomplete stored agent identity")
		}
		return nil
	}
	if !protocol.ValidUUID(s.ClusterID) || strings.TrimSpace(s.ClusterUID) == "" || len(s.ClusterUID) > 128 {
		return fmt.Errorf("stored agent identity is missing a valid cluster ID or UID")
	}
	if len(s.PendingKey) != 0 && bytes.Equal(s.PrivateKey, s.PendingKey) {
		return fmt.Errorf("pending rotation key must differ from current identity key")
	}
	return nil
}

func validPrivateKey(key []byte) bool {
	return len(key) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key)
}

type Store interface {
	Load(context.Context) (State, error)
	Save(context.Context, *State) error
}

// FileStore is intended for isolated local use with one running agent process.
type FileStore struct{ Path string }

func (f FileStore) Load(context.Context) (State, error) {
	var s State
	dir := filepath.Dir(f.Path)
	if err := validateStateDirectory(dir); err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	info, err := os.Lstat(f.Path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return s, fmt.Errorf("agent state must be a regular file inaccessible to group and other users")
	}
	file, err := os.Open(f.Path)
	if err != nil {
		return s, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return s, err
	}
	pathInfo, err := os.Lstat(f.Path)
	if err != nil || !os.SameFile(info, openedInfo) || !os.SameFile(info, pathInfo) {
		return s, fmt.Errorf("agent state file changed while it was being opened")
	}
	b, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil {
		return s, err
	}
	if len(b) > 8192 {
		return s, fmt.Errorf("state exceeds maximum size")
	}
	if err = json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	return s, s.Validate()
}
func (f FileStore) Save(_ context.Context, s *State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := validateStateDirectory(dir); err != nil {
		return err
	}
	if err := validateExistingStateFile(f.Path); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".kordex-state-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer func() { _ = os.Remove(name) }()
	if err = file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, f.Path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func validateStateDirectory(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := abs; ; current = filepath.Dir(current) {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			if filepath.Clean(resolved) != current {
				return fmt.Errorf("agent state directory path must not traverse symlinks")
			}
			break
		}
		if !os.IsNotExist(resolveErr) {
			return resolveErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return resolveErr
		}
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("agent state directory must be a real directory not writable by group or other users")
	}
	return nil
}

func validateExistingStateFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("existing agent state must be a regular file inaccessible to group and other users")
	}
	return nil
}

// KubernetesStore updates one pre-created Secret using resource-version compare-and-swap.
type KubernetesStore struct {
	Client          kubernetes.Interface
	Namespace, Name string
}

func (k KubernetesStore) Load(ctx context.Context) (State, error) {
	var s State
	secret, err := k.Client.CoreV1().Secrets(k.Namespace).Get(ctx, k.Name, metav1.GetOptions{})
	if err != nil {
		return s, err
	}
	if b := secret.Data["state.json"]; len(b) > 0 {
		if err = json.Unmarshal(b, &s); err != nil {
			return s, err
		}
	}
	s.Revision = secret.ResourceVersion
	return s, s.Validate()
}
func (k KubernetesStore) Save(ctx context.Context, s *State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	secret, err := k.Client.CoreV1().Secrets(k.Namespace).Get(ctx, k.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if secret.ResourceVersion != s.Revision {
		return fmt.Errorf("agent state changed concurrently; reload before continuing")
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data["state.json"] = b
	updated, err := k.Client.CoreV1().Secrets(k.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	s.Revision = updated.ResourceVersion
	return nil
}
