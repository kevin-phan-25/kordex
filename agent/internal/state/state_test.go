package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFileRestartAndPermissions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	store := FileStore{Path: path}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	original := State{ClusterID: "11111111-1111-4111-8111-111111111111", ClusterUID: "uid", PrivateKey: key, Version: 42}
	if err := store.Save(ctx, &original); err != nil {
		t.Fatal(err)
	}
	loaded, err := (FileStore{Path: path}).Load(ctx)
	if err != nil || loaded.Version != 42 || string(loaded.PrivateKey) != string(key) {
		t.Fatal("state not durable")
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("private identity has unsafe permissions")
	}
}

func TestFileStoreRejectsInsecureStateFilesAndDirectories(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "identity.json")
	store := FileStore{Path: path}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := State{ClusterID: "11111111-1111-4111-8111-111111111111", ClusterUID: "uid", PrivateKey: key}
	if err = store.Save(ctx, &state); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(ctx); err == nil {
		t.Fatal("accepted group/world-readable identity state")
	}
	if err = store.Save(ctx, &state); err == nil {
		t.Fatal("overwrote group/world-readable identity state")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "identity-link.json")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = (FileStore{Path: link}).Load(ctx); err == nil {
		t.Fatal("accepted symlinked identity state")
	}
	if err = (FileStore{Path: link}).Save(ctx, &state); err == nil {
		t.Fatal("overwrote symlinked identity state")
	}
	privateDir := filepath.Join(root, "private-dir")
	if err = os.Mkdir(privateDir, 0700); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(root, "private-dir-link")
	if err = os.Symlink(privateDir, dirLink); err != nil {
		t.Fatal(err)
	}
	dirStore := FileStore{Path: filepath.Join(dirLink, "other.json")}
	if _, err = dirStore.Load(ctx); err == nil {
		t.Fatal("accepted a symlinked state directory")
	}
	if err = dirStore.Save(ctx, &state); err == nil {
		t.Fatal("created state through a symlinked state directory")
	}
	if err = os.Chmod(root, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(ctx); err == nil {
		t.Fatal("accepted identity state in a group-writable directory")
	}
	if err = store.Save(ctx, &state); err == nil {
		t.Fatal("saved identity state in a group-writable directory")
	}
}

func TestFileStoreInitializesMissingPrivateDirectory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "identity.json")
	store := FileStore{Path: path}
	if _, err := store.Load(ctx); err != nil {
		t.Fatalf("missing initial state should be empty: %v", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := State{ClusterID: "11111111-1111-4111-8111-111111111111", ClusterUID: "uid", PrivateKey: key}
	if err = store.Save(ctx, &state); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(ctx); err != nil {
		t.Fatalf("saved state did not reload: %v", err)
	}
}

func TestValidateRejectsPartialOrResettingIdentityState(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, pending, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := State{ClusterID: "11111111-1111-4111-8111-111111111111", ClusterUID: "uid", PrivateKey: key, Version: 1}
	if err = valid.Validate(); err != nil {
		t.Fatalf("valid initialized state rejected: %v", err)
	}
	if err = (State{}).Validate(); err != nil {
		t.Fatalf("empty first-run state rejected: %v", err)
	}
	for name, state := range map[string]State{
		"cluster ID without key":          {ClusterID: valid.ClusterID, ClusterUID: valid.ClusterUID},
		"UID without key":                 {ClusterUID: valid.ClusterUID},
		"key without cluster ID":          {ClusterUID: valid.ClusterUID, PrivateKey: key},
		"key without cluster UID":         {ClusterID: valid.ClusterID, PrivateKey: key},
		"version without identity":        {Version: 1},
		"pending key without current key": {PendingKey: pending},
		"duplicate rotation key":          {ClusterID: valid.ClusterID, ClusterUID: valid.ClusterUID, PrivateKey: key, PendingKey: key},
		"inconsistent current key bytes":  {ClusterID: valid.ClusterID, ClusterUID: valid.ClusterUID, PrivateKey: make([]byte, ed25519.PrivateKeySize)},
		"inconsistent pending key bytes":  {ClusterID: valid.ClusterID, ClusterUID: valid.ClusterUID, PrivateKey: key, PendingKey: make([]byte, ed25519.PrivateKeySize)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := state.Validate(); err == nil {
				t.Fatal("accepted incomplete or identity-reset state")
			}
		})
	}
	valid.PendingKey = pending
	if err = valid.Validate(); err != nil {
		t.Fatalf("valid pending key rotation rejected: %v", err)
	}
}

func TestFileStoreRejectsPartiallyInitializedStateOnRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte(`{"clusterId":"11111111-1111-4111-8111-111111111111","clusterUid":"uid","version":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Path: path}).Load(context.Background()); err == nil {
		t.Fatal("treated partial persisted identity as a fresh installation")
	}
}
func TestProjectedSecretStoreLoadsProjectedFileAndPatchesWithoutSecretRead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	versioned := filepath.Join(dir, "..2026_11_19_00_00_00.000000001")
	if err := os.Mkdir(versioned, 0755); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := State{ClusterID: "11111111-1111-4111-8111-111111111111", ClusterUID: "uid", PrivateKey: key, Version: 7}
	stateJSON, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	versionedFile := filepath.Join(versioned, "state.json")
	if err = os.WriteFile(versionedFile, stateJSON, 0400); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Base(versioned), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	projectedPath := filepath.Join(dir, "state.json")
	if err = os.Symlink(filepath.Join("..data", "state.json"), projectedPath); err != nil {
		t.Fatal(err)
	}
	initialData := base64.StdEncoding.EncodeToString(stateJSON)
	kube := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "identity", Namespace: "test"},
		Data:       map[string][]byte{"state.json": stateJSON},
	})
	store := ProjectedSecretStore{Client: kube, Namespace: "test", Name: "identity", Path: projectedPath}
	loaded, err := store.Load(ctx)
	if err != nil || loaded.Version != original.Version || string(loaded.PrivateKey) != string(key) {
		t.Fatalf("projected identity failed to load: state=%+v err=%v", loaded, err)
	}
	if loaded.Revision != "v1:"+initialData {
		t.Fatal("projected revision did not capture the current state for compare-and-swap")
	}
	loaded.Version++
	stale := loaded
	stale.Version++
	if err = store.Save(ctx, &loaded); err != nil {
		t.Fatal(err)
	}
	if err = store.Save(ctx, &stale); err == nil {
		t.Fatal("accepted a stale projected identity writer")
	}
	for _, action := range kube.Actions() {
		if action.GetVerb() == "get" && action.GetResource().Resource == "secrets" {
			t.Fatal("agent state store read a Kubernetes Secret through the API")
		}
	}
	patchAction, ok := kube.Actions()[0].(interface {
		GetVerb() string
		GetPatchType() types.PatchType
		GetPatch() []byte
	})
	if !ok || patchAction.GetPatchType() != types.JSONPatchType || !bytes.Contains(patchAction.GetPatch(), []byte("state.json")) {
		t.Fatal("identity persistence did not use a state-key JSON Patch")
	}
}

func TestProjectedSecretStoreInitializesWithoutSecretRead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kube := fake.NewClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "identity", Namespace: "test"}})
	store := ProjectedSecretStore{Client: kube, Namespace: "test", Name: "identity", Path: filepath.Join(dir, "state.json")}
	state, err := store.Load(ctx)
	if err != nil || state.Revision != "absent" {
		t.Fatalf("empty projected Secret was not treated as a new identity: state=%+v err=%v", state, err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state.ClusterID = "11111111-1111-4111-8111-111111111111"
	state.ClusterUID = "uid"
	state.PrivateKey = key
	if err = store.Save(ctx, &state); err != nil {
		t.Fatal(err)
	}
	actions := kube.Actions()
	if len(actions) != 1 {
		t.Fatalf("expected one Secret patch, got %d Kubernetes actions", len(actions))
	}
	patchAction, ok := actions[0].(interface {
		GetVerb() string
		GetPatchType() types.PatchType
		GetPatch() []byte
	})
	if !ok || patchAction.GetVerb() != "patch" || patchAction.GetPatchType() != types.MergePatchType {
		t.Fatal("initial state was not written with a Secret merge patch")
	}
}

func TestProjectedSecretStoreRejectsSymlinkEscapeAndBroadPermissions(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "state.json")
	if err := os.WriteFile(outsideFile, []byte(`{}`), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "state.json")
	if err := os.Symlink(filepath.Join("..data", "state.json"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := readProjectedState(path); err == nil {
		t.Fatal("accepted an identity file outside its projected Secret volume")
	}

	if err := os.Remove(filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	widePath := filepath.Join(root, "state.json")
	if err := os.WriteFile(widePath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readProjectedState(widePath); err == nil {
		t.Fatal("accepted identity state readable by other users")
	}
}
