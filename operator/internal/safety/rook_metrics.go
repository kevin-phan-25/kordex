package safety

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const rookMetricsPort = int32(9283)
const rookMetricsResponseLimit = 64 << 20
const rookMetricsMaxSampleAge = time.Minute
const rookMetricsFutureSkew = 5 * time.Second

// RookMetricsSource returns one fresh metrics exposition from the manager
// endpoint in the namespace containing a Rook CephCluster.
type RookMetricsSource interface {
	Scrape(context.Context, string) ([]byte, error)
}

// RookServiceMetrics discovers the cluster-local Rook manager metrics Service
// and scrapes its Prometheus endpoint. The service identity is derived from
// Kubernetes labels rather than operator-provided URLs.
type RookServiceMetrics struct {
	Reader     client.Reader
	HTTPClient *http.Client
	TLSConfig  *tls.Config
}

// RookMetricsTLSConfig loads a private CA bundle for verifying an HTTPS Rook
// manager endpoint. It never enables insecure certificate verification.
func RookMetricsTLSConfig(caFile string) (*tls.Config, error) {
	if caFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Rook metrics CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("Rook metrics CA bundle contains no certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
}

func (s RookServiceMetrics) Scrape(ctx context.Context, namespace string) ([]byte, error) {
	if s.Reader == nil || namespace == "" {
		return nil, fmt.Errorf("Rook metrics service identity is incomplete")
	}
	var services corev1.ServiceList
	if err := s.Reader.List(ctx, &services,
		client.InNamespace(namespace),
		client.MatchingLabels{"app": "rook-ceph-mgr", "rook_cluster": namespace},
	); err != nil {
		return nil, fmt.Errorf("list Rook manager metrics services: %w", err)
	}
	var service *corev1.Service
	var port int32
	useTLS := false
	for i := range services.Items {
		candidate := &services.Items[i]
		for _, servicePort := range candidate.Spec.Ports {
			if servicePort.Port != rookMetricsPort {
				continue
			}
			if service != nil {
				return nil, fmt.Errorf("multiple Rook manager metrics services found")
			}
			useTLS = (servicePort.AppProtocol != nil && strings.EqualFold(*servicePort.AppProtocol, "https")) || strings.Contains(strings.ToLower(servicePort.Name), "https")
			service = candidate
			port = servicePort.Port
		}
	}
	if service == nil || port < 1 {
		return nil, fmt.Errorf("Rook manager metrics service on port %d not found", rookMetricsPort)
	}
	if service.Spec.ClusterIP == corev1.ClusterIPNone || service.Spec.ClusterIP == "" {
		return nil, fmt.Errorf("Rook metrics service has no stable cluster IP")
	}

	scheme := "http"
	metricsClient := s.HTTPClient
	if metricsClient == nil {
		metricsClient = &http.Client{Timeout: 5 * time.Second}
	}
	if useTLS {
		if s.TLSConfig == nil || s.TLSConfig.RootCAs == nil || s.TLSConfig.InsecureSkipVerify || s.TLSConfig.ServerName != "" {
			return nil, fmt.Errorf("HTTPS Rook metrics requires a configured private CA bundle")
		}
		scheme = "https"
		clientCopy := *metricsClient
		transport := clientCopy.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		standardTransport, ok := transport.(*http.Transport)
		if !ok || standardTransport.DialTLS != nil || standardTransport.DialTLSContext != nil {
			return nil, fmt.Errorf("HTTPS Rook metrics requires a verifiable HTTP transport")
		}
		secureTransport := standardTransport.Clone()
		secureTransport.TLSClientConfig = s.TLSConfig.Clone()
		secureTransport.TLSClientConfig.MinVersion = tls.VersionTLS12
		clientCopy.Transport = secureTransport
		metricsClient = &clientCopy
	}
	host := net.JoinHostPort(service.Name+"."+namespace+".svc", strconv.Itoa(int(port)))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/metrics", nil)
	if err != nil {
		return nil, fmt.Errorf("build Rook metrics request: %w", err)
	}
	request.Header.Set("Accept", "text/plain; version=0.0.4; charset=utf-8")
	response, err := metricsClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("scrape Rook manager metrics: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Rook metrics endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, rookMetricsResponseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read Rook metrics response: %w", err)
	}
	if len(body) > rookMetricsResponseLimit {
		return nil, fmt.Errorf("Rook metrics response exceeded size limit")
	}
	return body, nil
}

func evaluateRookMetrics(body []byte, expectedOSDs map[string]struct{}) Result {
	return evaluateRookMetricsAt(body, expectedOSDs, time.Now().UTC())
}

func evaluateRookMetricsAt(body []byte, expectedOSDs map[string]struct{}, now time.Time) Result {
	if len(body) == 0 || len(body) > rookMetricsResponseLimit || len(expectedOSDs) == 0 {
		return Block("RookCephMetricsInvalid")
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		return Block("RookCephMetricsParseFailed")
	}
	// A successful HTTP scrape does not make explicitly timestamped exporter
	// samples fresh. Validate every safety signal before interpreting its value;
	// exporters that omit timestamps are evaluated at this scrape's observation
	// time, as is standard for Prometheus exposition.
	for _, name := range []string{
		"ceph_health_status", "ceph_osd_up", "ceph_osd_in", "ceph_osd_flag_noout",
		"ceph_pg_backfill", "ceph_pg_recovering", "ceph_pg_forced_backfill",
		"ceph_pg_forced_recovery", "ceph_pg_degraded", "ceph_pg_down",
		"ceph_pg_stale", "ceph_pg_undersized", "ceph_pg_inconsistent",
		"ceph_health_detail",
	} {
		if family := families[name]; family != nil && !freshMetricFamily(family, now) {
			return Block("RookCephMetricsStale")
		}
	}
	health, ok := oneMetricValue(families, "ceph_health_status")
	if !ok {
		return Block("RookCephHealthMetricUnknown")
	}
	if health != 0 {
		return Block("RookCephMetricsHealthNotOK")
	}

	up, ok := osdStates(families, "ceph_osd_up")
	if !ok {
		return Block("RookCephOSDUpEvidenceUnknown")
	}
	in, ok := osdStates(families, "ceph_osd_in")
	if !ok {
		return Block("RookCephOSDInEvidenceUnknown")
	}
	if !sameIDs(up, expectedOSDs) || !sameIDs(in, expectedOSDs) {
		return Block("RookCephOSDMetricsInventoryMismatch")
	}
	for id := range expectedOSDs {
		if up[id] != 1 {
			return Block("RookCephOSDDown")
		}
		if in[id] != 1 {
			return Block("RookCephOSDOut")
		}
	}

	noout, ok := familyValues(families, "ceph_osd_flag_noout")
	if !ok || len(noout) == 0 {
		return Block("RookCephNooutEvidenceUnknown")
	}
	for _, value := range noout {
		if value != 0 {
			return Block("RookCephNooutActive")
		}
	}
	for _, metric := range []string{
		"ceph_pg_backfill",
		"ceph_pg_recovering",
		"ceph_pg_forced_backfill",
		"ceph_pg_forced_recovery",
		"ceph_pg_degraded",
		"ceph_pg_down",
		"ceph_pg_stale",
		"ceph_pg_undersized",
		"ceph_pg_inconsistent",
	} {
		value, ok := oneMetricValue(families, metric)
		if !ok {
			return Block("RookCephRecoveryEvidenceUnknown")
		}
		if value != 0 {
			return Block("RookCephRecoveryOrDegradationActive")
		}
	}
	if family := families["ceph_health_detail"]; family != nil {
		for _, metric := range family.GetMetric() {
			name := metricLabel(metric, "name")
			if name != "OSDMAP_FLAGS" && name != "OSD_FLAGS" {
				continue
			}
			value, valid := metricValue(metric)
			if !valid || value != 0 {
				return Block("RookCephOSDFlagsActiveOrUnknown")
			}
		}
	}
	return Pass()
}

func freshMetricFamily(family *dto.MetricFamily, now time.Time) bool {
	for _, metric := range family.GetMetric() {
		if metric.TimestampMs == nil {
			continue
		}
		observedAt := time.UnixMilli(metric.GetTimestampMs())
		if observedAt.Before(now.Add(-rookMetricsMaxSampleAge)) || observedAt.After(now.Add(rookMetricsFutureSkew)) {
			return false
		}
	}
	return true
}

func oneMetricValue(families map[string]*dto.MetricFamily, name string) (float64, bool) {
	values, ok := familyValues(families, name)
	if !ok || len(values) != 1 {
		return 0, false
	}
	return values[0], true
}

func familyValues(families map[string]*dto.MetricFamily, name string) ([]float64, bool) {
	family := families[name]
	if family == nil || len(family.GetMetric()) == 0 {
		return nil, false
	}
	values := make([]float64, 0, len(family.GetMetric()))
	for _, metric := range family.GetMetric() {
		value, ok := metricValue(metric)
		if !ok {
			return nil, false
		}
		values = append(values, value)
	}
	return values, true
}

func metricValue(metric *dto.Metric) (float64, bool) {
	var value float64
	switch {
	case metric.GetGauge() != nil:
		value = metric.GetGauge().GetValue()
	case metric.GetUntyped() != nil:
		value = metric.GetUntyped().GetValue()
	case metric.GetCounter() != nil:
		value = metric.GetCounter().GetValue()
	default:
		return 0, false
	}
	return value, !math.IsNaN(value) && !math.IsInf(value, 0)
}

func osdStates(families map[string]*dto.MetricFamily, name string) (map[string]float64, bool) {
	family := families[name]
	if family == nil || len(family.GetMetric()) == 0 {
		return nil, false
	}
	states := make(map[string]float64, len(family.GetMetric()))
	for _, metric := range family.GetMetric() {
		id := metricLabel(metric, "ceph_daemon")
		if strings.HasPrefix(id, "osd.") {
			id = strings.TrimPrefix(id, "osd.")
		}
		if id == "" {
			id = metricLabel(metric, "id")
		}
		if id == "" {
			return nil, false
		}
		if _, err := strconv.ParseUint(id, 10, 32); err != nil {
			return nil, false
		}
		if _, duplicate := states[id]; duplicate {
			return nil, false
		}
		value, ok := metricValue(metric)
		if !ok || (value != 0 && value != 1) {
			return nil, false
		}
		states[id] = value
	}
	return states, true
}

func metricLabel(metric *dto.Metric, key string) string {
	for _, pair := range metric.GetLabel() {
		if pair.GetName() == key {
			return pair.GetValue()
		}
	}
	return ""
}

func sameIDs(actual map[string]float64, expected map[string]struct{}) bool {
	if len(actual) != len(expected) {
		return false
	}
	for id := range expected {
		if _, exists := actual[id]; !exists {
			return false
		}
	}
	return true
}
