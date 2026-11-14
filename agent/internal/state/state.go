// Package state persists identity and sequence checkpoints before network side effects.
package state

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
	if len(s.PrivateKey) != 0 && len(s.PrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid stored private key")
	}
	if len(s.PendingKey) != 0 && len(s.PendingKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid pending private key")
	}
	if s.Version < 0 {
		return fmt.Errorf("invalid inventory version")
	}
	return nil
}

type Store interface {
	Load(context.Context) (State, error)
	Save(context.Context, *State) error
}

// FileStore is intended for isolated local use with one running agent process.
type FileStore struct{ Path string }

func (f FileStore) Load(context.Context) (State, error) {
	var s State
	b, err := os.ReadFile(f.Path)
	if os.IsNotExist(err) {
		return s, nil
	}
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
