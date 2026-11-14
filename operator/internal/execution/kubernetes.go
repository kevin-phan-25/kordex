// Package execution contains only Kubernetes cordon and eviction actions; no host execution exists.
package execution

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"kordex.local/api/protocol"
)

const OwnerAnnotation = protocol.OperationGroup + "/cordon-owner"

type Evictor interface {
	Evict(context.Context, *corev1.Pod, int64) error
}
type KubernetesEvictor struct{ Client kubernetes.Interface }

func (e KubernetesEvictor) Evict(ctx context.Context, pod *corev1.Pod, grace int64) error {
	uid := pod.UID
	return e.Client.CoreV1().Pods(pod.Namespace).EvictV1(ctx, &policyv1.Eviction{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: pod.Namespace}, DeleteOptions: &metav1.DeleteOptions{GracePeriodSeconds: &grace, Preconditions: &metav1.Preconditions{UID: &uid}}})
}

// Cordon performs a compare-and-swap on node UID, resource version and ownership.
func Cordon(ctx context.Context, c client.Client, node *corev1.Node, owner string, cordon bool) error {
	if node.ResourceVersion == "" || node.UID == "" {
		return fmt.Errorf("node identity or version missing")
	}
	annotations := map[string]string{}
	for k, v := range node.Annotations {
		annotations[k] = v
	}
	if cordon {
		if current := annotations[OwnerAnnotation]; current != "" && current != owner {
			return fmt.Errorf("foreign cordon owner")
		}
		if node.Spec.Unschedulable && annotations[OwnerAnnotation] != owner {
			return fmt.Errorf("node already cordoned")
		}
		annotations[OwnerAnnotation] = owner
	} else {
		if annotations[OwnerAnnotation] != owner {
			return fmt.Errorf("operation does not own cordon")
		}
		delete(annotations, OwnerAnnotation)
	}
	patch := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(node.UID)}, {"op": "test", "path": "/metadata/resourceVersion", "value": node.ResourceVersion}, {"op": "add", "path": "/metadata/annotations", "value": annotations}, {"op": "add", "path": "/spec/unschedulable", "value": cordon}}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	return c.Patch(ctx, node, client.RawPatch(types.JSONPatchType, data))
}
