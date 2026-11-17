package safety

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	corev1 "k8s.io/api/core/v1"
)

const EtcdMemberIDLabel = "operations.kordex.local/etcd-member-id"

// EtcdQuorum obtains live membership and per-member status over mutually
// authenticated TLS. It is evidence only: it never changes membership or
// invokes etcdctl. A target node must carry the exact member ID label.
type EtcdQuorum struct {
	Probe     EtcdProbe
	Endpoints []string
	Timeout   time.Duration
}

type EtcdProbe interface {
	Members(context.Context) ([]EtcdVoter, uint64, error)
	Status(context.Context, string) (EtcdMemberStatus, error)
}

type EtcdVoter struct {
	ID      uint64
	Learner bool
}

type EtcdMemberStatus struct {
	ID        uint64
	ClusterID uint64
	Revision  int64
	RaftTerm  uint64
}

func (q EtcdQuorum) Check(ctx context.Context, node *corev1.Node) (Result, error) {
	if node == nil {
		return Block("EtcdTargetIdentityUnknown"), nil
	}
	isControlPlane := ControlPlane(node)
	if q.Probe == nil {
		if !isControlPlane {
			return Pass(), nil
		}
		return Block("ControlPlaneQuorumAdapterRequired"), nil
	}
	targetID := uint64(0)
	if isControlPlane {
		var err error
		targetID, err = strconv.ParseUint(node.Labels[EtcdMemberIDLabel], 16, 64)
		if err != nil || targetID == 0 {
			return Block("EtcdTargetMemberIdentityUnknown"), nil
		}
	}
	timeout := q.Timeout
	if timeout <= 0 || timeout > 15*time.Second {
		timeout = 5 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	members, clusterID, err := q.Probe.Members(probeCtx)
	if err != nil || clusterID == 0 || len(members) == 0 {
		return Block("EtcdMembershipUnavailable"), nil
	}
	seen := make(map[uint64]EtcdVoter, len(members))
	targetFound := false
	voters, healthyVoters := 0, 0
	for _, member := range members {
		if member.ID == 0 {
			return Block("EtcdMemberIdentityUnknown"), nil
		}
		if _, exists := seen[member.ID]; exists {
			return Block("EtcdMembershipContradictory"), nil
		}
		seen[member.ID] = member
		if isControlPlane && member.ID == targetID {
			targetFound = true
		}
		if !member.Learner {
			voters++
		}
	}
	if voters == 0 {
		return Block("EtcdVoterInventoryUnknown"), nil
	}
	if isControlPlane && !targetFound {
		return Block("EtcdTargetNotInMembership"), nil
	}

	observed := make(map[uint64]EtcdMemberStatus, len(members))
	if len(q.Endpoints) == 0 {
		return Block("EtcdEndpointsUnknown"), nil
	}
	for _, endpoint := range q.Endpoints {
		status, statusErr := q.Probe.Status(probeCtx, endpoint)
		if statusErr != nil || status.ID == 0 || status.ClusterID != clusterID || status.Revision < 1 || status.RaftTerm < 1 {
			return Block("EtcdMemberHealthUnknown"), nil
		}
		member, exists := seen[status.ID]
		if !exists {
			return Block("EtcdMembershipContradictory"), nil
		}
		if _, duplicate := observed[status.ID]; duplicate {
			return Block("EtcdMembershipContradictory"), nil
		}
		observed[status.ID] = status
		if !member.Learner {
			healthyVoters++
		}
	}
	if len(observed) != len(members) {
		return Block("EtcdMemberHealthUnknown"), nil
	}
	if isControlPlane {
		if _, targetHealthy := observed[targetID]; !targetHealthy {
			return Block("EtcdTargetMemberUnhealthy"), nil
		}
	}
	// A control-plane voter being stopped leaves the original majority
	// threshold. Worker maintenance checks the current majority without removal.
	if isControlPlane && !seen[targetID].Learner {
		healthyVoters--
	}
	if healthyVoters < voters/2+1 {
		return Block("EtcdQuorumWouldBeLost"), nil
	}
	return Pass(), nil
}

// NewEtcdQuorumFromEnv builds the optional live adapter. With no endpoints,
// workers retain the worker-only policy and control-plane nodes remain blocked.
func NewEtcdQuorumFromEnv() (Quorum, func() error, error) {
	endpointValue := strings.TrimSpace(os.Getenv("KORDEX_ETCD_ENDPOINTS"))
	if endpointValue == "" {
		return WorkerOnlyQuorum{}, func() error { return nil }, nil
	}
	endpoints := strings.Split(endpointValue, ",")
	if len(endpoints) < 1 || len(endpoints) > 9 {
		return nil, nil, errors.New("KORDEX_ETCD_ENDPOINTS must configure between one and nine members")
	}
	seen := make(map[string]struct{}, len(endpoints))
	for i := range endpoints {
		endpoints[i] = strings.TrimSpace(endpoints[i])
		parsed, err := url.Parse(endpoints[i])
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, nil, errors.New("KORDEX_ETCD_ENDPOINTS must contain HTTPS origins only")
		}
		if _, exists := seen[endpoints[i]]; exists {
			return nil, nil, errors.New("KORDEX_ETCD_ENDPOINTS cannot contain duplicate origins")
		}
		seen[endpoints[i]] = struct{}{}
	}
	caPath, certPath, keyPath := os.Getenv("KORDEX_ETCD_CA_FILE"), os.Getenv("KORDEX_ETCD_CERT_FILE"), os.Getenv("KORDEX_ETCD_KEY_FILE")
	if caPath == "" || certPath == "" || keyPath == "" {
		return nil, nil, errors.New("etcd endpoints require CA, client certificate, and key files")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read etcd CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("invalid etcd CA bundle")
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load etcd client certificate: %w", err)
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: endpoints, DialTimeout: 5 * time.Second, DialKeepAliveTime: 15 * time.Second, DialKeepAliveTimeout: 5 * time.Second, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}})
	if err != nil {
		return nil, nil, fmt.Errorf("create etcd quorum client: %w", err)
	}
	return EtcdQuorum{Probe: etcdV3Probe{client: client}, Endpoints: endpoints}, client.Close, nil
}

type etcdV3Probe struct {
	client *clientv3.Client
}

func (p etcdV3Probe) Members(ctx context.Context) ([]EtcdVoter, uint64, error) {
	response, err := p.client.MemberList(ctx)
	if err != nil {
		return nil, 0, err
	}
	if response == nil || response.Header == nil {
		return nil, 0, errors.New("missing etcd membership header")
	}
	members := make([]EtcdVoter, 0, len(response.Members))
	for _, member := range response.Members {
		if member == nil || member.ID == 0 {
			return nil, 0, errors.New("invalid etcd member")
		}
		members = append(members, EtcdVoter{ID: uint64(member.ID), Learner: member.IsLearner})
	}
	return members, response.Header.ClusterId, nil
}

func (p etcdV3Probe) Status(ctx context.Context, endpoint string) (EtcdMemberStatus, error) {
	status, err := p.client.Status(ctx, endpoint)
	if err != nil {
		return EtcdMemberStatus{}, err
	}
	if status == nil || status.Header == nil {
		return EtcdMemberStatus{}, errors.New("missing etcd status header")
	}
	return EtcdMemberStatus{ID: status.Header.MemberId, ClusterID: status.Header.ClusterId, Revision: status.Header.Revision, RaftTerm: status.RaftTerm}, nil
}
