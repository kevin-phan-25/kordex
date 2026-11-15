// Package operations delivers hub-authorized work into a durable Kubernetes CRD inbox.
package operations

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"kordex.local/agent/internal/client"
	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
)

var Resource = schema.GroupVersionResource{Group: protocol.OperationGroup, Version: protocol.OperationVersion, Resource: protocol.OperationResource}

type Bridge struct {
	Remote     *client.Client
	Dynamic    dynamic.Interface
	Kubernetes kubernetes.Interface
	Namespace  string
}

func (b *Bridge) Sync(ctx context.Context, key ed25519.PrivateKey) error {
	inbox := b.Dynamic.Resource(Resource).Namespace(b.Namespace)
	input := protocol.OperationSync{Reports: []protocol.OperationReport{}}
	reported := map[string]int64{}
	continuation := ""
	for {
		list, err := inbox.List(ctx, metav1.ListOptions{Limit: 100, Continue: continuation, LabelSelector: protocol.OperationGroup + "/cluster-id=" + b.Remote.ClusterID})
		if err != nil {
			return fmt.Errorf("read durable operation inbox: %w", err)
		}
		for i := range list.Items {
			var m operations.NodeMaintenance
			if err = runtime.DefaultUnstructuredConverter.FromUnstructured(list.Items[i].Object, &m); err != nil {
				return err
			}
			var permit protocol.MaintenancePermit
			if err = json.Unmarshal([]byte(m.Spec.Authorization), &permit); err != nil || permit.MaintenanceRequest.Validate() != nil || permit.ClusterID != b.Remote.ClusterID {
				return fmt.Errorf("invalid durable operation envelope")
			}
			sequence := m.Status.Sequence
			acked := int64(0)
			if value := m.Annotations[protocol.AckAnnotation]; value != "" {
				parsed, err := strconv.ParseInt(value, 10, 64)
				if err != nil || parsed < 0 {
					return fmt.Errorf("invalid durable acknowledgement")
				}
				acked = parsed
			}
			if sequence < 1 || sequence <= acked {
				continue
			}
			report := protocol.OperationReport{OperationID: permit.OperationID, Sequence: sequence, Phase: m.Status.Phase, Reason: m.Status.Reason, Events: m.Status.Events}
			if !report.Validate() {
				return fmt.Errorf("invalid operator status checkpoint")
			}
			input.Reports = append(input.Reports, report)
			reported[permit.OperationID] = sequence
			if len(input.Reports) == 10 {
				break
			}
		}
		if len(input.Reports) == 10 || list.GetContinue() == "" {
			break
		}
		continuation = list.GetContinue()
	}
	started := time.Now()
	var response protocol.OperationSyncResult
	if err := b.Remote.Call(ctx, "POST", "/v1/agent/operations/sync", input, &response, key); err != nil {
		return err
	}
	if response.ServerTime.IsZero() || response.ServerTime.Before(started.Add(-5*time.Second)) || response.ServerTime.After(time.Now().Add(5*time.Second)) || len(response.Commands) > 1 || len(response.Controls) > 1 {
		return fmt.Errorf("invalid maintenance synchronization response")
	}
	for _, command := range response.Commands {
		var p protocol.MaintenancePermit
		if json.Unmarshal([]byte(command.Authorization), &p) != nil || p.MaintenanceRequest.Validate() != nil || p.ClusterID != b.Remote.ClusterID || len(command.Signature) != 86 {
			return fmt.Errorf("invalid maintenance command")
		}
		// The operator independently verifies the hub signature, cluster UID, policy and freshness.
		m := operations.NodeMaintenance{TypeMeta: metav1.TypeMeta{APIVersion: operations.GroupVersion.String(), Kind: "NodeMaintenance"}, ObjectMeta: metav1.ObjectMeta{Name: "op-" + p.OperationID, Namespace: b.Namespace, Finalizers: []string{protocol.OperationFinalizer}, Labels: map[string]string{protocol.OperationGroup + "/cluster-id": b.Remote.ClusterID}}, Spec: operations.NodeMaintenanceSpec{Authorization: command.Authorization, Signature: command.Signature}}
		data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&m)
		if err != nil {
			return err
		}
		_, err = inbox.Create(ctx, &unstructured.Unstructured{Object: data}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			existing, err := inbox.Get(ctx, m.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			authorization, _, _ := unstructured.NestedString(existing.Object, "spec", "authorization")
			signature, _, _ := unstructured.NestedString(existing.Object, "spec", "signature")
			if authorization != command.Authorization || signature != command.Signature {
				return fmt.Errorf("operation ID payload conflict")
			}
		} else if err != nil {
			return err
		}
	}
	for _, control := range response.Controls {
		if control.ClusterID != b.Remote.ClusterID || !protocol.ValidUUID(control.OperationID) {
			return fmt.Errorf("invalid cancellation delivery")
		}
		object, err := inbox.Get(ctx, "op-"+control.OperationID, metav1.GetOptions{})
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(control)
		if err != nil {
			return err
		}
		patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"resourceVersion": object.GetResourceVersion(), "annotations": map[string]string{protocol.CancellationAnnotation: string(encoded)}}})
		if err != nil {
			return err
		}
		if _, err = inbox.Patch(ctx, object.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return err
		}
	}
	for id, sequence := range response.Acknowledged {
		sent, ok := reported[id]
		if !ok || sequence < sent {
			continue
		}
		object, err := inbox.Get(ctx, "op-"+id, metav1.GetOptions{})
		if err != nil {
			return err
		}
		patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"resourceVersion": object.GetResourceVersion(), "annotations": map[string]string{protocol.AckAnnotation: strconv.FormatInt(sent, 10)}}})
		if err != nil {
			return err
		}
		if _, err = inbox.Patch(ctx, object.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return err
		}
	}
	lease, err := b.Kubernetes.CoordinationV1().Leases(b.Namespace).Get(ctx, protocol.ConnectionLease, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "" && *lease.Spec.HolderIdentity != b.Remote.ClusterID {
		return fmt.Errorf("connection lease belongs to another cluster")
	}
	holder := b.Remote.ClusterID
	renewed := metav1.NewMicroTime(response.ServerTime)
	duration := int32(protocol.ConnectionTTL.Seconds())
	lease.Spec.HolderIdentity = &holder
	lease.Spec.RenewTime = &renewed
	lease.Spec.LeaseDurationSeconds = &duration
	_, err = b.Kubernetes.CoordinationV1().Leases(b.Namespace).Update(ctx, lease, metav1.UpdateOptions{})
	return err
}
