// Package state persists identity and sequence checkpoints before network side effects.
package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

// ProjectedSecretStore reads identity through kubelet's read-only Secret volume
// and updates only the state key with JSON Patch compare-and-swap. The agent
// therefore needs patch permission for its named Secret, but no Secret read.
type ProjectedSecretStore struct {
	Client          kubernetes.Interface
	Namespace, Name string
	Path            string
}

func (k ProjectedSecretStore) Load(_ context.Context) (State, error) {
	var s State
	if k.Path == "" {
		return s, fmt.Errorf("projected agent state path is required")
	}
	b, err := readProjectedState(k.Path)
	if err != nil {
		return s, err
	}
	if len(b) > 0 {
		if err = json.Unmarshal(b, &s); err != nil {
			return s, err
		}
		s.Revision = "v1:" + base64.StdEncoding.EncodeToString(b)
	} else {
		s.Revision = "absent"
	}
	return s, s.Validate()
}

func (k ProjectedSecretStore) Save(ctx context.Context, s *State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if k.Client == nil || k.Namespace == "" || k.Name == "" || k.Path == "" {
		return fmt.Errorf("projected identity Secret client, namespace, name, and path are required")
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if s.Revision == "absent" {
		return fmt.Errorf("projected identity Secret has no compare-and-swap seed; initialize state.json to {} before starting the agent")
	}
	if !strings.HasPrefix(s.Revision, "v1:") {
		return fmt.Errorf("agent state has no projected Secret revision; reload before saving")
	}
	updated := base64.StdEncoding.EncodeToString(b)
	patch, err := json.Marshal([]map[string]any{
		{"op": "test", "path": "/data/state.json", "value": strings.TrimPrefix(s.Revision, "v1:")},
		{"op": "replace", "path": "/data/state.json", "value": updated},
	})
	if err != nil {
		return err
	}
	if _, err = k.Client.CoreV1().Secrets(k.Namespace).Patch(ctx, k.Name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return err
	}
	s.Revision = "v1:" + updated
	return nil
}

func readProjectedState(path string) ([]byte, error) {
	root, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	resolvedRoot = filepath.Clean(resolvedRoot)
	resolvedFile, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedFile)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("projected identity file must resolve within its Secret volume")
	}
	// Walk the already-resolved path from an opened mount directory. O_NOFOLLOW
	// on every component prevents a swapped kubelet symlink (or a replaced path
	// component) from redirecting the read after EvalSymlinks completed.
	file, err := openProjectedFile(resolvedRoot, rel)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	perm := openedInfo.Mode().Perm()
	if !openedInfo.Mode().IsRegular() || perm&0037 != 0 || perm&0444 == 0 {
		return nil, fmt.Errorf("projected identity must be a regular Secret file without group write or other access")
	}
	b, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil {
		return nil, err
	}
	if len(b) > 8192 {
		return nil, fmt.Errorf("projected identity state exceeds maximum size")
	}
	return b, nil
}

func openProjectedFile(root, relative string) (*os.File, error) {
	if filepath.IsAbs(relative) {
		return nil, fmt.Errorf("projected identity path must be relative to its Secret volume")
	}
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	if len(parts) == 0 {
		return nil, fmt.Errorf("projected identity path is empty")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("projected identity path contains an unsafe component")
		}
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(fd, part, flags, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), filepath.Join(root, relative)), nil
}
