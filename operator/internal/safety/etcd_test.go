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

func healthyEtcdStatus(id uint64, revision int64) EtcdMemberStatus {
	return EtcdMemberStatus{
		ID: id, ClusterID: 99, LeaderID: 10, Revision: revision,
		RaftTerm: 7, RaftIndex: 120, RaftAppliedIndex: 120,
	}
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
			endpoints[0]: healthyEtcdStatus(10, 100),
			endpoints[1]: healthyEtcdStatus(11, 101),
			endpoints[2]: healthyEtcdStatus(12, 99),
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
			endpoints[0]: healthyEtcdStatus(10, 100),
			endpoints[1]: healthyEtcdStatus(11, 101),
			endpoints[2]: healthyEtcdStatus(11, 99),
		},
	}
	result, err := (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), node)
	if err != nil || result.Allowed || result.Reason != "EtcdMembershipContradictory" {
		t.Fatalf("duplicate endpoint identity must fail closed, got %+v, %v", result, err)
	}

	probe.status[endpoints[2]] = healthyEtcdStatus(12, 99)
	probe.errors = map[string]error{endpoints[2]: errors.New("member unavailable")}
	result, err = (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), node)
	if err != nil || result.Allowed || result.Reason != "EtcdMemberHealthUnknown" {
		t.Fatalf("unknown third voter cannot grant quorum, got %+v, %v", result, err)
	}
}

func TestEtcdQuorumRequiresHealthyConsistentConsensusView(t *testing.T) {
	node := &corev1.Node{}
	endpoints := []string{"https://etcd-a:2379", "https://etcd-b:2379", "https://etcd-c:2379"}
	newProbe := func() fakeEtcdProbe {
		return fakeEtcdProbe{
			members: []EtcdVoter{{ID: 10}, {ID: 11}, {ID: 12}}, cluster: 99,
			status: map[string]EtcdMemberStatus{
				endpoints[0]: healthyEtcdStatus(10, 100),
				endpoints[1]: healthyEtcdStatus(11, 101),
				endpoints[2]: healthyEtcdStatus(12, 99),
			},
		}
	}
	tests := []struct {
		name   string
		mutate func(*fakeEtcdProbe)
		reason string
	}{
		{
			name: "member reports errors", reason: "EtcdMemberHealthUnknown",
			mutate: func(p *fakeEtcdProbe) {
				status := p.status[endpoints[1]]
				status.Errors = []string{"NOSPACE"}
				p.status[endpoints[1]] = status
			},
		},
		{
			name: "member has unapplied raft entries", reason: "EtcdMemberHealthUnknown",
			mutate: func(p *fakeEtcdProbe) {
				status := p.status[endpoints[1]]
				status.RaftAppliedIndex = status.RaftIndex + 1
				p.status[endpoints[1]] = status
			},
		},
		{
			name: "members disagree on leader", reason: "EtcdConsensusViewInconsistent",
			mutate: func(p *fakeEtcdProbe) {
				status := p.status[endpoints[2]]
				status.LeaderID = 11
				p.status[endpoints[2]] = status
			},
		},
		{
			name: "members disagree on term", reason: "EtcdConsensusViewInconsistent",
			mutate: func(p *fakeEtcdProbe) {
				status := p.status[endpoints[2]]
				status.RaftTerm++
				p.status[endpoints[2]] = status
			},
		},
		{
			name: "reported leader is not a member", reason: "EtcdLeaderIdentityUnknown",
			mutate: func(p *fakeEtcdProbe) {
				for endpoint, status := range p.status {
					status.LeaderID = 99
					p.status[endpoint] = status
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := newProbe()
			test.mutate(&probe)
			result, err := (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), node)
			if err != nil || result.Allowed || result.Reason != test.reason {
				t.Fatalf("unsafe etcd evidence must block as %q, got result=%+v err=%v", test.reason, result, err)
			}
		})
	}
}

func TestEtcdQuorumDoesNotImplyControlPlaneEligibilityForWorkers(t *testing.T) {
	worker := &corev1.Node{}
	result, err := (EtcdQuorum{}).Check(context.Background(), worker)
	if err != nil || !result.Allowed {
		t.Fatalf("ordinary worker must not require etcd, got %+v, %v", result, err)
	}
	result, err = (EtcdQuorum{Endpoints: []string{"https://etcd-a:2379"}}).Check(context.Background(), worker)
	if err != nil || result.Allowed || result.Reason != "EtcdProbeUnavailable" {
		t.Fatalf("configured etcd without a live probe must fail closed, got %+v, %v", result, err)
	}
	endpoints := []string{"https://etcd-a:2379", "https://etcd-b:2379", "https://etcd-c:2379"}
	probe := fakeEtcdProbe{
		members: []EtcdVoter{{ID: 10}, {ID: 11}, {ID: 12}}, cluster: 99,
		status: map[string]EtcdMemberStatus{
			endpoints[0]: healthyEtcdStatus(10, 100),
			endpoints[1]: healthyEtcdStatus(11, 101),
			endpoints[2]: healthyEtcdStatus(12, 99),
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

func TestEtcdMemberLabelTriggersProjectedQuorumWithoutKubernetesRoleLabel(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{EtcdMemberIDLabel: "a"}}}
	if !ControlPlane(node) {
		t.Fatal("explicit etcd member mapping did not classify target as control-plane infrastructure")
	}
	endpoints := []string{"https://etcd-a:2379", "https://etcd-b:2379"}
	probe := fakeEtcdProbe{
		members: []EtcdVoter{{ID: 10}, {ID: 11}}, cluster: 99,
		status: map[string]EtcdMemberStatus{
			endpoints[0]: healthyEtcdStatus(10, 100),
			endpoints[1]: healthyEtcdStatus(11, 101),
		},
	}
	result, err := (EtcdQuorum{Probe: probe, Endpoints: endpoints}).Check(context.Background(), node)
	if err != nil || result.Allowed || result.Reason != "EtcdQuorumWouldBeLost" {
		t.Fatalf("taking an explicitly mapped etcd voter offline must project the remaining quorum: result=%+v err=%v", result, err)
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
