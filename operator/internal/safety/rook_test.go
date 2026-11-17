package safety

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRookCephStorageRequiresFreshHealthyEvidenceAndReadyOSDs(t *testing.T) {
	now := time.Now().UTC()
	cluster := rookTestCluster(now)
	pods := []runtime.Object{
		rookTestOSD("osd-a", "storage-a", "0"),
		rookTestOSD("osd-b", "storage-b", "1"),
		rookTestOSD("osd-c", "storage-c", "2"),
	}
	readerScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(readerScheme); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(readerScheme).WithRuntimeObjects(pods...).Build()
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cluster)
	storage := RookCephStorage{Reader: reader, Dynamic: dyn, Metrics: rookMetricsFixture(), Now: func() time.Time { return now }}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-a"}}
	if result, err := storage.Check(context.Background(), node, nil); err != nil || !result.Allowed {
		t.Fatalf("healthy Ceph cluster blocked unrelated worker: result=%+v err=%v", result, err)
	}
	node.Name = "storage-a"
	if result, err := storage.Check(context.Background(), node, nil); err != nil || result.Allowed || result.Reason != "CephOSDHostMaintenanceAdapterRequired" {
		t.Fatalf("OSD host must be blocked: result=%+v err=%v", result, err)
	}

	stale := rookTestCluster(now.Add(-3 * time.Minute))
	storage.Dynamic = dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), stale)
	node.Name = "worker-a"
	if result, err := storage.Check(context.Background(), node, nil); err != nil || result.Allowed || result.Reason != "RookCephEvidenceStale" {
		t.Fatalf("stale health evidence must block: result=%+v err=%v", result, err)
	}
}

func TestRookOSDHostMaintenanceAlwaysBlocksEvenWithManagedPDB(t *testing.T) {
	now := time.Now().UTC()
	readerScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(readerScheme); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(readerScheme).WithRuntimeObjects(
		rookTestOSD("osd-a", "storage-a", "0"),
		rookTestOSD("osd-b", "storage-b", "1"),
		rookTestOSD("osd-c", "storage-c", "2"),
	).Build()
	storage := RookCephStorage{
		Reader:  reader,
		Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), rookTestCluster(now)),
		Metrics: rookMetricsFixture(),
		Now:     func() time.Time { return now },
	}
	for _, nodeName := range []string{"storage-a", "storage-b", "storage-c"} {
		t.Run(nodeName, func(t *testing.T) {
			result, err := storage.Check(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}, nil)
			if err != nil || result.Allowed || result.Reason != "CephOSDHostMaintenanceAdapterRequired" {
				t.Fatalf("OSD host must remain blocked: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestRookCephStorageBlocksWhenOSDNotReadyOrHealthDegraded(t *testing.T) {
	now := time.Now().UTC()
	readerScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(readerScheme); err != nil {
		t.Fatal(err)
	}
	notReady := rookTestOSD("osd-a", "storage-a", "0")
	notReady.(*corev1.Pod).Status.Conditions[0].Status = corev1.ConditionFalse
	reader := fake.NewClientBuilder().WithScheme(readerScheme).WithRuntimeObjects(
		notReady,
		rookTestOSD("osd-b", "storage-b", "1"),
		rookTestOSD("osd-c", "storage-c", "2"),
	).Build()
	storage := RookCephStorage{Reader: reader, Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), rookTestCluster(now)), Metrics: rookMetricsFixture(), Now: func() time.Time { return now }}
	if result, err := storage.Check(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-a"}}, nil); err != nil || result.Allowed || result.Reason != "RookCephOSDNotReady" {
		t.Fatalf("unready OSD must block: result=%+v err=%v", result, err)
	}

	degraded := rookTestCluster(now)
	_ = unstructured.SetNestedField(degraded.Object, "HEALTH_WARN", "status", "ceph", "health")
	storage.Dynamic = dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), degraded)
	if result, err := storage.Check(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-a"}}, nil); err != nil || result.Allowed || result.Reason != "RookCephHealthNotOK" {
		t.Fatalf("degraded Ceph must block: result=%+v err=%v", result, err)
	}
}

func TestRookDefersOnlyItsObservedManagedOSDPDBBeforeCordon(t *testing.T) {
	cluster := rookTestCluster(time.Now().UTC())
	cluster.Object["spec"] = map[string]interface{}{"disruptionManagement": map[string]interface{}{"managePodBudgets": true}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "rook-ceph", Name: "rook-ceph-osd-0", Labels: map[string]string{"app": "rook-ceph-osd", "ceph-osd-id": "0"}}}
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: "rook-ceph", Name: "rook-ceph-osd", Labels: map[string]string{"app": "rook-ceph-osd"}}, Spec: policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "rook-ceph-osd"}}}}
	storage := RookCephStorage{Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cluster)}
	deferPDB, err := storage.DeferPDBUntilCordon(context.Background(), pod, pdb)
	if err != nil || !deferPDB {
		t.Fatalf("observed Rook-managed OSD budget should defer before cordon: defer=%t err=%v", deferPDB, err)
	}
	pdb.Name = "application-budget"
	deferPDB, err = storage.DeferPDBUntilCordon(context.Background(), pod, pdb)
	if err != nil || deferPDB {
		t.Fatalf("application budget must not be deferred: defer=%t err=%v", deferPDB, err)
	}
	// The exception is specific to the exact Rook-managed budget. A similarly
	// named budget with a selector that does not match the OSD is not deferred.
	pdb.Name = "rook-ceph-osd"
	pdb.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "some-other-workload"}}
	deferPDB, err = storage.DeferPDBUntilCordon(context.Background(), pod, pdb)
	if err != nil || deferPDB {
		t.Fatalf("non-matching OSD budget must not be deferred: defer=%t err=%v", deferPDB, err)
	}
}

func TestEvaluateRookMetricsFailsClosedOnOSDStorageOrRecoveryProblems(t *testing.T) {
	expected := map[string]struct{}{"0": {}, "1": {}, "2": {}}
	base := rookMetricsFixture()
	cases := []struct {
		name   string
		body   string
		reason string
	}{
		{name: "osd down", body: strings.Replace(string(base), `ceph_osd_up{ceph_daemon="osd.1"} 1`, `ceph_osd_up{ceph_daemon="osd.1"} 0`, 1), reason: "RookCephOSDDown"},
		{name: "osd out", body: strings.Replace(string(base), `ceph_osd_in{ceph_daemon="osd.1"} 1`, `ceph_osd_in{ceph_daemon="osd.1"} 0`, 1), reason: "RookCephOSDOut"},
		{name: "noout set", body: strings.Replace(string(base), `ceph_osd_flag_noout{ceph_daemon="osd.0"} 0`, `ceph_osd_flag_noout{ceph_daemon="osd.0"} 1`, 1), reason: "RookCephNooutActive"},
		{name: "backfill active", body: strings.Replace(string(base), `ceph_pg_backfill 0`, `ceph_pg_backfill 1`, 1), reason: "RookCephRecoveryOrDegradationActive"},
		{name: "recovery metric absent", body: strings.Replace(string(base), "ceph_pg_recovering 0\n", "", 1), reason: "RookCephRecoveryEvidenceUnknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evaluateRookMetrics([]byte(tc.body), expected); got.Allowed || got.Reason != tc.reason {
				t.Fatalf("result=%+v, want block %q", got, tc.reason)
			}
		})
	}
}

func TestRookServiceMetricsUsesOnlyMatchingClusterService(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rook-ceph-mgr", Namespace: "storage-system",
			Labels: map[string]string{"app": "rook-ceph-mgr", "rook_cluster": "storage-system"},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.10",
			Ports:     []corev1.ServicePort{{Name: "http-metrics", Port: 9283}},
		},
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(service).Build()
	called := false
	source := RookServiceMetrics{Reader: reader, HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		if request.Method != http.MethodGet || request.URL.Host != "rook-ceph-mgr.storage-system.svc:9283" || request.URL.Path != "/metrics" {
			t.Fatalf("unexpected Rook metrics request URL=%s method=%s", request.URL, request.Method)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ceph_health_status 0\n")), Header: make(http.Header)}, nil
	})}}
	body, err := source.Scrape(context.Background(), "storage-system")
	if err != nil || !called || string(body) != "ceph_health_status 0\n" {
		t.Fatalf("scrape body=%q called=%t err=%v", body, called, err)
	}

	service.Spec.Ports[0].AppProtocol = stringPointer("https")
	reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(service).Build()
	source.Reader = reader
	if _, err := source.Scrape(context.Background(), "storage-system"); err == nil {
		t.Fatal("TLS metrics endpoint should fail closed")
	}
}

func rookTestCluster(checkedAt time.Time) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "ceph.rook.io/v1",
		"kind":       "CephCluster",
		"metadata":   map[string]interface{}{"name": "rook-ceph", "namespace": "rook-ceph", "generation": int64(1)},
		"status": map[string]interface{}{
			"state":              "Created",
			"observedGeneration": int64(1),
			"ceph":               map[string]interface{}{"health": "HEALTH_OK", "lastChecked": checkedAt.Format(time.RFC3339)},
			"storage":            map[string]interface{}{"osd": map[string]interface{}{"storeType": map[string]interface{}{"bluestore": int64(3)}}},
		},
	}}
}

func rookTestOSD(name, node, id string) runtime.Object {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "rook-ceph", Labels: map[string]string{"app": "rook-ceph-osd", "ceph-osd-id": id}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

type rookMetricsFixtureSource []byte

func (s rookMetricsFixtureSource) Scrape(context.Context, string) ([]byte, error) {
	return s, nil
}

func rookMetricsFixture() rookMetricsFixtureSource {
	return rookMetricsFixtureSource([]byte(`# TYPE ceph_health_status untyped
ceph_health_status 0
# TYPE ceph_osd_up untyped
ceph_osd_up{ceph_daemon="osd.0"} 1
ceph_osd_up{ceph_daemon="osd.1"} 1
ceph_osd_up{ceph_daemon="osd.2"} 1
# TYPE ceph_osd_in untyped
ceph_osd_in{ceph_daemon="osd.0"} 1
ceph_osd_in{ceph_daemon="osd.1"} 1
ceph_osd_in{ceph_daemon="osd.2"} 1
# TYPE ceph_osd_flag_noout gauge
ceph_osd_flag_noout{ceph_daemon="osd.0"} 0
ceph_osd_flag_noout{ceph_daemon="osd.1"} 0
ceph_osd_flag_noout{ceph_daemon="osd.2"} 0
# TYPE ceph_pg_backfill gauge
ceph_pg_backfill 0
# TYPE ceph_pg_recovering gauge
ceph_pg_recovering 0
# TYPE ceph_pg_forced_backfill gauge
ceph_pg_forced_backfill 0
# TYPE ceph_pg_forced_recovery gauge
ceph_pg_forced_recovery 0
# TYPE ceph_pg_degraded gauge
ceph_pg_degraded 0
# TYPE ceph_pg_down gauge
ceph_pg_down 0
# TYPE ceph_pg_stale gauge
ceph_pg_stale 0
# TYPE ceph_pg_undersized gauge
ceph_pg_undersized 0
# TYPE ceph_pg_inconsistent gauge
ceph_pg_inconsistent 0
`))
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func stringPointer(value string) *string { return &value }
