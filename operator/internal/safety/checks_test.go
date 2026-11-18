package safety

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type readyAPIServer struct{}

func (readyAPIServer) Ready(context.Context) error { return nil }

func TestClusterHealthScopesPendingJobsToTargetNode(t *testing.T) {
	for _, test := range []struct {
		name       string
		jobNode    string
		wantReason string
	}{
		{name: "unrelated pending job does not block", jobNode: "worker-2"},
		{name: "pending job on target blocks", jobNode: "worker-1", wantReason: "ClusterWorkloadDegraded"},
		{name: "unscheduled job blocks as potential capacity pressure", jobNode: "", wantReason: "ClusterWorkloadDegraded"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			scheme := runtime.NewScheme()
			for _, add := range []func(*runtime.Scheme) error{
				corev1.AddToScheme,
				appsv1.AddToScheme,
				coordinationv1.AddToScheme,
			} {
				if err := add(scheme); err != nil {
					t.Fatal(err)
				}
			}
			objects := []runtime.Object{
				readyWorker("worker-1", now),
				readyWorker("worker-2", now),
				readyLease("worker-1", now),
				readyLease("worker-2", now),
				pendingJobPod(test.jobNode),
			}
			reader := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
			checker := Checker{Reader: reader, API: readyAPIServer{}, Now: func() time.Time { return now }}
			_, result, err := checker.Cluster(context.Background(), "worker-1", nil)
			if err != nil {
				t.Fatalf("Cluster() error = %v", err)
			}
			if test.wantReason != "" && result.Reason != test.wantReason {
				t.Fatalf("Cluster() reason = %q, want %q (allowed=%v)", result.Reason, test.wantReason, result.Allowed)
			}
			if test.wantReason == "" && !result.Allowed {
				t.Fatalf("unrelated batch Job blocked maintenance: %+v", result)
			}
		})
	}
}

func readyWorker(name string, now time.Time) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-time.Minute))},
			{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
			{Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse},
			{Type: corev1.NodePIDPressure, Status: corev1.ConditionFalse},
		}},
	}
}

func readyLease(node string, now time.Time) *coordinationv1.Lease {
	renewTime := metav1.NewMicroTime(now)
	return &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-node-lease", Name: node}, Spec: coordinationv1.LeaseSpec{RenewTime: &renewTime}}
}

func pendingJobPod(node string) *corev1.Pod {
	controller := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "batch", Name: "pending-job", UID: types.UID("pending-job-pod"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "pending-job", UID: types.UID("pending-job"), Controller: &controller}}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
}
