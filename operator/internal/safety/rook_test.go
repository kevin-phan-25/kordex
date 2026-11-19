package safety

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	dyn := rookTestDynamic(cluster)
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
	storage.Dynamic = rookTestDynamic(stale)
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
		Dynamic: rookTestDynamic(rookTestCluster(now)),
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
	storage := RookCephStorage{Reader: reader, Dynamic: rookTestDynamic(rookTestCluster(now)), Metrics: rookMetricsFixture(), Now: func() time.Time { return now }}
	if result, err := storage.Check(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-a"}}, nil); err != nil || result.Allowed || result.Reason != "RookCephOSDNotReady" {
		t.Fatalf("unready OSD must block: result=%+v err=%v", result, err)
	}

	degraded := rookTestCluster(now)
	_ = unstructured.SetNestedField(degraded.Object, "HEALTH_WARN", "status", "ceph", "health")
	storage.Dynamic = rookTestDynamic(degraded)
	if result, err := storage.Check(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-a"}}, nil); err != nil || result.Allowed || result.Reason != "RookCephHealthNotOK" {
		t.Fatalf("degraded Ceph must block: result=%+v err=%v", result, err)
	}
}

func TestRookDefersOnlyItsObservedManagedOSDPDBBeforeCordon(t *testing.T) {
	cluster := rookTestCluster(time.Now().UTC())
	cluster.Object["spec"] = map[string]interface{}{"disruptionManagement": map[string]interface{}{"managePodBudgets": true}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "rook-ceph", Name: "rook-ceph-osd-0", Labels: map[string]string{"app": "rook-ceph-osd", "ceph-osd-id": "0"}}}
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: "rook-ceph", Name: "rook-ceph-osd", Labels: map[string]string{"app": "rook-ceph-osd"}}, Spec: policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "rook-ceph-osd"}}}}
	storage := RookCephStorage{Dynamic: rookTestDynamic(cluster)}
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

	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	staleHealth := strings.Replace(string(base), "ceph_health_status 0\n", "ceph_health_status 0 1794916739000\n", 1)
	if got := evaluateRookMetricsAt([]byte(staleHealth), expected, now); got.Allowed || got.Reason != "RookCephMetricsStale" {
		t.Fatalf("stale timestamped Ceph health metric must block: result=%+v", got)
	}
	futureOSD := strings.Replace(string(base), `ceph_osd_up{ceph_daemon="osd.1"} 1`, `ceph_osd_up{ceph_daemon="osd.1"} 1 1794916806000`, 1)
	if got := evaluateRookMetricsAt([]byte(futureOSD), expected, now); got.Allowed || got.Reason != "RookCephMetricsStale" {
		t.Fatalf("future timestamped Ceph OSD metric must block: result=%+v", got)
	}
	if got := evaluateRookMetricsAt(base, expected, now); !got.Allowed {
		t.Fatalf("untimestamped samples from the current scrape should remain valid: result=%+v", got)
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

func TestRookServiceMetricsVerifiesHTTPSUsingConfiguredPrivateCA(t *testing.T) {
	const serviceHost = "rook-ceph-mgr.storage-system.svc"
	caPEM, serverCertificate := rookMetricsTestCertificate(t, serviceHost)
	caFile := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := RookMetricsTLSConfig(caFile)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "ceph_health_status 0\n")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	reader := rookMetricsServiceReader(t, "https")
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	source := RookServiceMetrics{Reader: reader, HTTPClient: &http.Client{Transport: transport, Timeout: 2 * time.Second}, TLSConfig: tlsConfig}
	body, err := source.Scrape(context.Background(), "storage-system")
	if err != nil || string(body) != "ceph_health_status 0\n" {
		t.Fatalf("trusted HTTPS scrape body=%q err=%v", body, err)
	}
	unsafeTLS := tlsConfig.Clone()
	unsafeTLS.InsecureSkipVerify = true
	if _, err = (RookServiceMetrics{Reader: reader, TLSConfig: unsafeTLS}).Scrape(context.Background(), "storage-system"); err == nil {
		t.Fatal("HTTPS scrape accepted InsecureSkipVerify")
	}
	wrongServerName := tlsConfig.Clone()
	wrongServerName.ServerName = "unrelated.example"
	if _, err = (RookServiceMetrics{Reader: reader, TLSConfig: wrongServerName}).Scrape(context.Background(), "storage-system"); err == nil {
		t.Fatal("HTTPS scrape accepted a TLS server-name override")
	}
	unsafeDialTLS := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	}}
	if _, err = (RookServiceMetrics{Reader: reader, HTTPClient: &http.Client{Transport: unsafeDialTLS}, TLSConfig: tlsConfig}).Scrape(context.Background(), "storage-system"); err == nil {
		t.Fatal("HTTPS scrape accepted a custom TLS dialer")
	}

	wrongCAFile := t.TempDir() + "/wrong-ca.crt"
	if err = os.WriteFile(wrongCAFile, []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = RookMetricsTLSConfig(wrongCAFile); err == nil {
		t.Fatal("malformed CA bundle was accepted")
	}
	wrongConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()}
	wrongSource := RookServiceMetrics{Reader: reader, HTTPClient: &http.Client{Transport: transport, Timeout: 2 * time.Second}, TLSConfig: wrongConfig}
	if _, err = wrongSource.Scrape(context.Background(), "storage-system"); err == nil {
		t.Fatal("HTTPS Rook metrics accepted an untrusted server certificate")
	}
}

func TestRookMetricsTLSConfigRejectsMissingOrInvalidCA(t *testing.T) {
	if config, err := RookMetricsTLSConfig(""); err != nil || config != nil {
		t.Fatalf("empty CA path should leave HTTP-only behavior configured: config=%v err=%v", config, err)
	}
	if _, err := RookMetricsTLSConfig(t.TempDir() + "/missing-ca.crt"); err == nil {
		t.Fatal("missing CA bundle was accepted")
	}
	path := t.TempDir() + "/invalid-ca.crt"
	if err := os.WriteFile(path, []byte("not pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RookMetricsTLSConfig(path); err == nil {
		t.Fatal("invalid CA bundle was accepted")
	}
}

func rookMetricsServiceReader(t *testing.T, protocol string) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "rook-ceph-mgr", Namespace: "storage-system", Labels: map[string]string{"app": "rook-ceph-mgr", "rook_cluster": "storage-system"}},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.0.0.10", Ports: []corev1.ServicePort{{Name: "https-metrics", Port: 9283, AppProtocol: &protocol}}},
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(service).Build()
}

func rookMetricsTestCertificate(t *testing.T, hostname string) ([]byte, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Kordex test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certificate := tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverKey}
	return caPEM, certificate
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

func rookTestDynamic(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	listKinds := longhornListKinds()
	listKinds[rookCephClusters] = "CephClusterList"
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)
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
