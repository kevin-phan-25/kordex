package safety

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeEtcdProbe struct {
	members []EtcdVoter
	cluster uint64
	status  map[string]EtcdMemberStatus
	errors  map[string]error
}

func (f fakeEtcdProbe) Members(context.Context) ([]EtcdVoter, uint64, error) {
	return f.members, f.cluster, nil
}

func (f fakeEtcdProbe) Status(_ context.Context, endpoint string) (EtcdMemberStatus, error) {
	if err := f.errors[endpoint]; err != nil {
		return EtcdMemberStatus{}, err
	}
	return f.status[endpoint], nil
}

func TestEtcdQuorumRequiresLiveCompleteMembershipAndRemainingMajority(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
		"node-role.kubernetes.io/control-plane": "",
		EtcdMemberIDLabel:                       "a",
	}}}
	endpoints := []string{"https://etcd-a:2379", "https://etcd-b:2379", "https://etcd-c:2379"}
	probe := fakeEtcdProbe{
		members: []EtcdVoter{{ID: 10}, {ID: 11}, {ID: 12}}, cluster: 99,
		status: map[string]EtcdMemberStatus{
			endpoints[0]: {ID: 10, ClusterID: 99, Revision: 100, RaftTerm: 7},
			endpoints[1]: {ID: 11, ClusterID: 99, Revision: 101, RaftTerm: 7},
			endpoints[2]: {ID: 12, ClusterID: 99, Revision: 99, RaftTerm: 7},
		},
	}
	result, err := (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), node)
	if err != nil || !result.Allowed {
		t.Fatalf("expected healthy remaining majority, got %+v, %v", result, err)
	}

	probe.errors = map[string]error{endpoints[2]: errors.New("member unreachable")}
	result, err = (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), node)
	if err != nil || result.Allowed || result.Reason != "EtcdMemberHealthUnknown" {
		t.Fatalf("unreachable member must fail closed, got %+v, %v", result, err)
	}
}

func TestEtcdQuorumRejectsContradictoryStatusAndUnreachableMembers(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
		"node-role.kubernetes.io/control-plane": "",
		EtcdMemberIDLabel:                       "a",
	}}}
	endpoints := []string{"https://etcd-a:2379", "https://etcd-b:2379", "https://etcd-c:2379"}
	probe := fakeEtcdProbe{
		members: []EtcdVoter{{ID: 10}, {ID: 11}, {ID: 12}}, cluster: 99,
		status: map[string]EtcdMemberStatus{
			endpoints[0]: {ID: 10, ClusterID: 99, Revision: 100, RaftTerm: 7},
			endpoints[1]: {ID: 11, ClusterID: 99, Revision: 101, RaftTerm: 7},
			endpoints[2]: {ID: 11, ClusterID: 99, Revision: 99, RaftTerm: 7},
		},
	}
	result, err := (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), node)
	if err != nil || result.Allowed || result.Reason != "EtcdMembershipContradictory" {
		t.Fatalf("duplicate endpoint identity must fail closed, got %+v, %v", result, err)
	}

	probe.status[endpoints[2]] = EtcdMemberStatus{ID: 12, ClusterID: 99, Revision: 99, RaftTerm: 7}
	probe.errors = map[string]error{endpoints[2]: errors.New("member unavailable")}
	result, err = (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), node)
	if err != nil || result.Allowed || result.Reason != "EtcdMemberHealthUnknown" {
		t.Fatalf("unknown third voter cannot grant quorum, got %+v, %v", result, err)
	}
}

func TestEtcdQuorumDoesNotImplyControlPlaneEligibilityForWorkers(t *testing.T) {
	worker := &corev1.Node{}
	result, err := (EtcdQuorum{}).Check(context.Background(), worker)
	if err != nil || !result.Allowed {
		t.Fatalf("ordinary worker must not require etcd, got %+v, %v", result, err)
	}
	endpoints := []string{"https://etcd-a:2379", "https://etcd-b:2379", "https://etcd-c:2379"}
	probe := fakeEtcdProbe{
		members: []EtcdVoter{{ID: 10}, {ID: 11}, {ID: 12}}, cluster: 99,
		status: map[string]EtcdMemberStatus{
			endpoints[0]: {ID: 10, ClusterID: 99, Revision: 100, RaftTerm: 7},
			endpoints[1]: {ID: 11, ClusterID: 99, Revision: 101, RaftTerm: 7},
			endpoints[2]: {ID: 12, ClusterID: 99, Revision: 99, RaftTerm: 7},
		},
	}
	result, err = (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), worker)
	if err != nil || !result.Allowed {
		t.Fatalf("healthy live etcd should allow worker safety check, got %+v, %v", result, err)
	}
	probe.errors = map[string]error{endpoints[1]: errors.New("member unreachable")}
	result, err = (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), worker)
	if err != nil || result.Allowed || result.Reason != "EtcdMemberHealthUnknown" {
		t.Fatalf("configured unhealthy etcd must block worker maintenance, got %+v, %v", result, err)
	}

	controlPlane := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}}
	result, err = (EtcdQuorum{}).Check(context.Background(), controlPlane)
	if err != nil || result.Allowed || result.Reason != "ControlPlaneQuorumAdapterRequired" {
		t.Fatalf("unconfigured control plane must remain blocked, got %+v, %v", result, err)
	}
}

func TestEtcdQuorumConfigurationRequiresHTTPSUniqueBoundedEndpointsAndTLS(t *testing.T) {
	t.Setenv("KORDEX_ETCD_ENDPOINTS", "http://etcd-1:2379")
	if _, _, err := NewEtcdQuorumFromEnv(); err == nil {
		t.Fatal("plain HTTP etcd endpoint accepted")
	}

	t.Setenv("KORDEX_ETCD_ENDPOINTS", "https://etcd-1:2379,https://etcd-1:2379")
	if _, _, err := NewEtcdQuorumFromEnv(); err == nil {
		t.Fatal("duplicate etcd endpoint accepted")
	}

	t.Setenv("KORDEX_ETCD_ENDPOINTS", "https://etcd-1:2379")
	t.Setenv("KORDEX_ETCD_CA_FILE", "")
	t.Setenv("KORDEX_ETCD_CERT_FILE", "")
	t.Setenv("KORDEX_ETCD_KEY_FILE", "")
	if _, _, err := NewEtcdQuorumFromEnv(); err == nil {
		t.Fatal("endpoint configured without mTLS material accepted")
	}

	t.Setenv("KORDEX_ETCD_ENDPOINTS", "")
	quorum, closeClient, err := NewEtcdQuorumFromEnv()
	if err != nil {
		t.Fatalf("default worker-only quorum configuration: %v", err)
	}
	if _, ok := quorum.(WorkerOnlyQuorum); !ok {
		t.Fatalf("no endpoints should preserve WorkerOnlyQuorum, got %T", quorum)
	}
	if err = closeClient(); err != nil {
		t.Fatalf("close default quorum: %v", err)
	}
}
