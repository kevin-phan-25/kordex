// Package reboot coordinates host maintenance with existing reboot daemons.
package reboot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

// LockAnnotation is kured's documented single-node lock. Kordex uses a manual
// holder, never a real node ID: https://kured.dev/docs/operation/ .
const LockAnnotation = "weave.works/kured-node-lock"

var ErrBusy = errors.New("kured lock is held by another owner")
var ErrLost = errors.New("kured lock ownership is missing or changed")

type Kured struct {
	Client    kubernetes.Interface
	Enabled   bool
	Namespace string
	Name      string
}

// Reference is persisted on NodeMaintenance before the external lock is taken.
// It pins the DaemonSet identity/configuration across restart and lost responses.
type Reference struct {
	Version    int       `json:"version"`
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	UID        types.UID `json:"uid"`
	SpecDigest string    `json:"specDigest"`
	Holder     string    `json:"holder"`
	Acquired   bool      `json:"acquired"`
}

func holder(owner types.UID) string { return "manual:kordex:" + string(owner) }

func lockValue(ref Reference) string {
	data, _ := json.Marshal(struct {
		NodeID string `json:"nodeID"`
	}{ref.Holder})
	// Omitted TTL is zero: this lock never expires automatically in kured.
	return string(data)
}

func specDigest(ds *appsv1.DaemonSet) string {
	data, _ := json.Marshal(ds.Spec)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (ref Reference) Validate(owner types.UID) error {
	digest, err := hex.DecodeString(ref.SpecDigest)
	if ref.Version != 1 || owner == "" || ref.Holder != holder(owner) || ref.UID == "" ||
		len(validation.IsDNS1123Label(ref.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 ||
		err != nil || len(digest) != sha256.Size {
		return errors.New("invalid persisted kured lock reference")
	}
	return nil
}

func ready(ds *appsv1.DaemonSet) bool {
	s := ds.Status
	return s.ObservedGeneration >= ds.Generation && s.DesiredNumberScheduled > 0 &&
		s.UpdatedNumberScheduled == s.DesiredNumberScheduled && s.NumberReady == s.DesiredNumberScheduled &&
		s.NumberAvailable == s.DesiredNumberScheduled && s.NumberUnavailable == 0 && s.NumberMisscheduled == 0
}

// validateConfiguration deliberately supports only reviewed, digest-pinned
// single-lock kured deployments. Arguments must use literal --name=value form;
// environment overrides must resolve locally without Kubernetes expansion.
func validateConfiguration(ds *appsv1.DaemonSet) error {
	if len(ds.Spec.Template.Spec.Containers) != 1 {
		return errors.New("kured interlock requires one explicit kured container")
	}
	c := ds.Spec.Template.Spec.Containers[0]
	_, digest, pinned := strings.Cut(c.Image, "@sha256:")
	decoded, err := hex.DecodeString(digest)
	if !pinned || err != nil || len(decoded) != sha256.Size || len(c.EnvFrom) != 0 ||
		len(c.Command) > 1 || len(c.Command) == 1 && c.Command[0] != "/usr/bin/kured" {
		return errors.New("kured requires a digest-pinned image, direct entrypoint, and explicit environment")
	}
	settings := map[string]string{"ds-namespace": "kube-system", "ds-name": "kured", "lock-annotation": LockAnnotation,
		"concurrency": "1", "lock-ttl": "0"}
	for _, arg := range c.Args {
		key, value, equal := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		// Restrict every flag, including unrelated ones: a split string flag can
		// consume the next token instead of letting kured parse it as a flag.
		if !strings.HasPrefix(arg, "--") || !equal || key == "" || strings.HasPrefix(key, "-") || strings.Contains(arg, "$(") {
			return errors.New("kured arguments must use literal --name=value form without interpolation")
		}
		if _, watched := settings[key]; watched {
			settings[key] = value
		}
	}
	seenEnvironment := make(map[string]bool)
	for _, env := range c.Env {
		key := strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(env.Name, "KURED_")), "_", "-")
		if !strings.HasPrefix(env.Name, "KURED_") {
			continue
		}
		if _, watched := settings[key]; !watched {
			continue
		}
		// kured looks up exact uppercase names. Do not let aliases or duplicate
		// entries mask the value its process will actually read.
		if env.Name != "KURED_"+strings.ToUpper(strings.ReplaceAll(key, "-", "_")) || seenEnvironment[key] {
			return errors.New("kured locking environment must use unique canonical names")
		}
		seenEnvironment[key] = true
		value := env.Value
		if env.ValueFrom != nil {
			if env.ValueFrom.FieldRef == nil || env.ValueFrom.FieldRef.FieldPath != "metadata.namespace" {
				return errors.New("kured locking environment must not depend on Secrets or ConfigMaps")
			}
			value = ds.Namespace
		}
		if strings.Contains(value, "$(") {
			return errors.New("kured locking environment must not use interpolation")
		}
		settings[key] = value
	}
	ttl, err := time.ParseDuration(settings["lock-ttl"])
	if err != nil || ttl != 0 || settings["concurrency"] != "1" || settings["ds-namespace"] != ds.Namespace ||
		settings["ds-name"] != ds.Name || settings["lock-annotation"] != LockAnnotation {
		return errors.New("kured must use concurrency=1, lock-ttl=0, and the configured DaemonSet lock")
	}
	return nil
}

func (k *Kured) Prepare(ctx context.Context, owner types.UID) (Reference, error) {
	ds, err := k.Client.AppsV1().DaemonSets(k.Namespace).Get(ctx, k.Name, metav1.GetOptions{})
	if err != nil {
		return Reference{}, err
	}
	if err := validateConfiguration(ds); err != nil {
		return Reference{}, err
	}
	if !ready(ds) {
		return Reference{}, errors.New("kured DaemonSet is not fully ready and current")
	}
	ref := Reference{Version: 1, Namespace: ds.Namespace, Name: ds.Name, UID: ds.UID, SpecDigest: specDigest(ds), Holder: holder(owner)}
	return ref, ref.Validate(owner)
}

func (k *Kured) load(ctx context.Context, ref Reference) (*appsv1.DaemonSet, error) {
	ds, err := k.Client.AppsV1().DaemonSets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if ds.UID != ref.UID || specDigest(ds) != ref.SpecDigest {
		return nil, errors.New("kured DaemonSet identity or configuration changed")
	}
	if err := validateConfiguration(ds); err != nil {
		return nil, err
	}
	return ds, nil
}

// Acquire uses the same resource-version CAS as kured; an uncertain response
// can be resolved by reading this exact manual holder on the next reconcile.
func (k *Kured) Acquire(ctx context.Context, ref Reference) error {
	ds, err := k.load(ctx, ref)
	if err != nil {
		return err
	}
	if !ready(ds) {
		return errors.New("kured DaemonSet is not ready for lock acquisition")
	}
	if value, exists := ds.Annotations[LockAnnotation]; exists {
		if value == lockValue(ref) {
			return nil
		}
		return ErrBusy // Includes malformed, expired, and multi-owner records.
	}
	patch := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": ds.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": ds.ResourceVersion}}
	if ds.Annotations == nil {
		patch = append(patch, map[string]any{"op": "add", "path": "/metadata/annotations", "value": map[string]string{LockAnnotation: lockValue(ref)}})
	} else {
		patch = append(patch, map[string]any{"op": "add", "path": "/metadata/annotations/" + escape(LockAnnotation), "value": lockValue(ref)})
	}
	data, _ := json.Marshal(patch)
	_, err = k.Client.AppsV1().DaemonSets(ref.Namespace).Patch(ctx, ref.Name, types.JSONPatchType, data, metav1.PatchOptions{})
	return err
}

func (k *Kured) Check(ctx context.Context, ref Reference) error {
	ds, err := k.load(ctx, ref)
	if err != nil {
		return err
	}
	if ds.Annotations[LockAnnotation] != lockValue(ref) {
		return ErrLost
	}
	return nil // A rebooting node's kured Pod need not be Ready during recovery.
}

// Release never deletes another owner or a replacement DaemonSet's lock.
// Missing/foreign holders are already released from this operation's view.
func (k *Kured) Release(ctx context.Context, ref Reference) error {
	ds, err := k.Client.AppsV1().DaemonSets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if ds.UID != ref.UID {
		return errors.New("cannot release lock on a replacement kured DaemonSet")
	}
	if ds.Annotations[LockAnnotation] != lockValue(ref) {
		return nil
	}
	data, err := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": ref.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": ds.ResourceVersion},
		{"op": "test", "path": "/metadata/annotations/" + escape(LockAnnotation), "value": lockValue(ref)},
		{"op": "remove", "path": "/metadata/annotations/" + escape(LockAnnotation)},
	})
	if err != nil {
		return fmt.Errorf("encode kured lock release: %w", err)
	}
	_, err = k.Client.AppsV1().DaemonSets(ref.Namespace).Patch(ctx, ref.Name, types.JSONPatchType, data, metav1.PatchOptions{})
	return err
}

func escape(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}
