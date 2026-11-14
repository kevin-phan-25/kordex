package operations

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	remote "kordex.local/agent/internal/client"
	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
)

func TestDurableDeliveryAcknowledgementAndDisconnect(t *testing.T) {
	ctx := context.Background()
	cluster := "11111111-1111-4111-8111-111111111111"
	id := "22222222-2222-4222-8222-222222222222"
	now := time.Now().UTC()
	_, hub, _ := ed25519.GenerateKey(rand.Reader)
	agentPublic, agentPrivate, _ := ed25519.GenerateKey(rand.Reader)
	command, err := protocol.SignMaintenance(protocol.MaintenancePermit{OrganizationID: "33333333-3333-4333-8333-333333333333", ClusterID: cluster, ClusterUID: "cluster-uid", MaintenanceRequest: protocol.MaintenanceRequest{OperationID: id, NodeName: "worker1", NodeUID: "node-uid", Action: protocol.ValidateOnly, Policy: protocol.PolicyReference{Name: "safe", UID: "policy-uid", Generation: 1}}, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute)}, hub)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	offline := false
	reports := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if !protocol.Verify(r, agentPublic, body, time.Now()) {
			t.Error("unsigned sync request")
		}
		if offline {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":"offline"}`))
			return
		}
		var input protocol.OperationSync
		if err = json.Unmarshal(body, &input); err != nil {
			t.Error(err)
		}
		response := protocol.OperationSyncResult{Commands: []protocol.MaintenanceCommand{command}, ServerTime: time.Now().UTC(), Acknowledged: map[string]int64{}}
		for _, report := range input.Reports {
			if !report.Validate() {
				t.Error("invalid status report")
			}
			reports++
			response.Acknowledged[report.OperationID] = report.Sequence
		}
		if err = json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client, err := remote.New(server.URL, cluster, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP = server.Client()
	scheme := runtime.NewScheme()
	if err = operations.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	dynamic := dynamicfake.NewSimpleDynamicClient(scheme)
	empty := ""
	kube := kubefake.NewClientset(&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: protocol.ConnectionLease, Namespace: "ops"}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &empty}})
	bridge := Bridge{Remote: client, Dynamic: dynamic, Kubernetes: kube, Namespace: "ops"}
	if err = bridge.Sync(ctx, agentPrivate); err != nil {
		t.Fatal(err)
	}
	inbox := dynamic.Resource(Resource).Namespace("ops")
	object, err := inbox.Get(ctx, "op-"+id, metav1.GetOptions{})
	if err != nil {
		t.Fatal("command not durably created")
	}
	lease, err := kube.CoordinationV1().Leases("ops").Get(ctx, protocol.ConnectionLease, metav1.GetOptions{})
	if err != nil || lease.Spec.RenewTime == nil || *lease.Spec.HolderIdentity != cluster {
		t.Fatal("hub connection not recorded after persistence")
	}
	var m operations.NodeMaintenance
	if err = runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &m); err != nil {
		t.Fatal(err)
	}
	m.Status = operations.NodeMaintenanceStatus{OperationID: id, Sequence: 1, Phase: "Pending", Reason: "RequestAccepted", Events: []protocol.PhaseEvent{{Sequence: 1, Phase: "Pending", Reason: "RequestAccepted", Time: metav1.Now()}}}
	data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&m)
	if err != nil {
		t.Fatal(err)
	}
	object.Object = data
	if _, err = inbox.UpdateStatus(ctx, object, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = bridge.Sync(ctx, agentPrivate); err != nil {
		t.Fatal(err)
	}
	acknowledged, err := inbox.Get(ctx, object.GetName(), metav1.GetOptions{})
	if err != nil || acknowledged.GetAnnotations()[protocol.AckAnnotation] != "1" {
		t.Fatal("acknowledgement not durable")
	}
	restarted := bridge
	if err = restarted.Sync(ctx, agentPrivate); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if reports != 1 {
		t.Errorf("status resent after durable acknowledgement: %d", reports)
	}
	offline = true
	mu.Unlock()
	before, _ := kube.CoordinationV1().Leases("ops").Get(ctx, protocol.ConnectionLease, metav1.GetOptions{})
	if err = restarted.Sync(ctx, agentPrivate); err == nil {
		t.Fatal("disconnection ignored")
	}
	after, _ := kube.CoordinationV1().Leases("ops").Get(ctx, protocol.ConnectionLease, metav1.GetOptions{})
	if !before.Spec.RenewTime.Equal(after.Spec.RenewTime) {
		t.Fatal("renewed authorization while hub disconnected")
	}
	// Existing operation payloads are immutable; conflicting delivery must not overwrite the inbox.
	bad := acknowledged.DeepCopy()
	spec := bad.Object["spec"].(map[string]any)
	spec["signature"] = "conflict"
	if _, err = inbox.Update(ctx, bad, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	offline = false
	mu.Unlock()
	if err = restarted.Sync(ctx, agentPrivate); err == nil {
		t.Fatal("operation payload conflict was accepted")
	}
}
