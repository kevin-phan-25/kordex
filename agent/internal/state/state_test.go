package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFileRestartAndPermissions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	store := FileStore{Path: path}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	original := State{ClusterID: "a", ClusterUID: "uid", PrivateKey: key, Version: 42}
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
func TestKubernetesStateRejectsStaleWriter(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "identity", Namespace: "test", ResourceVersion: "1"}})
	store := KubernetesStore{Client: kube, Namespace: "test", Name: "identity"}
	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := kube.CoreV1().Secrets("test").Get(ctx, "identity", metav1.GetOptions{})
	secret.ResourceVersion = "2"
	if _, err = kube.CoreV1().Secrets("test").Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = store.Save(ctx, &loaded); err == nil {
		t.Fatal("accepted stale state writer")
	}
}
