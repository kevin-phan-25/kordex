package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

var requestBuckets = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type requestMetricKey struct {
	method, route string
	status        int
}
type requestMetric struct {
	count   uint64
	sum     float64
	buckets [len(requestBuckets)]uint64
}
type httpMetrics struct {
	mu      sync.Mutex
	metrics map[requestMetricKey]requestMetric
	other   requestMetric
}

func newHTTPMetrics() *httpMetrics {
	return &httpMetrics{metrics: make(map[requestMetricKey]requestMetric)}
}

func (m *httpMetrics) record(method, route string, status int, elapsed time.Duration) {
	if route == "" {
		route = "unmatched"
	}
	key := requestMetricKey{method: method, route: route, status: status}
	seconds := elapsed.Seconds()
	m.mu.Lock()
	if _, exists := m.metrics[key]; !exists && len(m.metrics) >= 4096 {
		key = requestMetricKey{method: "OTHER", route: "other", status: 0}
		value := m.other
		value.count++
		value.sum += seconds
		for i, bucket := range requestBuckets {
			if seconds <= bucket {
				value.buckets[i]++
			}
		}
		m.other = value
		m.mu.Unlock()
		return
	}
	value := m.metrics[key]
	value.count++
	value.sum += seconds
	for i, bucket := range requestBuckets {
		if seconds <= bucket {
			value.buckets[i]++
		}
	}
	m.metrics[key] = value
	m.mu.Unlock()
}

func (m *httpMetrics) serveHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	keys := make([]requestMetricKey, 0, len(m.metrics))
	values := make(map[requestMetricKey]requestMetric, len(m.metrics))
	for key, value := range m.metrics {
		keys = append(keys, key)
		values[key] = value
	}
	other := m.other
	m.mu.Unlock()
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.route != b.route {
			return a.route < b.route
		}
		if a.method != b.method {
			return a.method < b.method
		}
		return a.status < b.status
	})
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintln(w, "# HELP kordex_http_server_requests_total Completed HTTP requests.")
	_, _ = fmt.Fprintln(w, "# TYPE kordex_http_server_requests_total counter")
	_, _ = fmt.Fprintln(w, "# HELP kordex_http_server_request_duration_seconds HTTP request latency in seconds.")
	_, _ = fmt.Fprintln(w, "# TYPE kordex_http_server_request_duration_seconds histogram")
	for _, key := range keys {
		value := values[key]
		labels := fmt.Sprintf(`method=%q,route=%q,status=%q`, key.method, key.route, strconv.Itoa(key.status))
		_, _ = fmt.Fprintf(w, "kordex_http_server_requests_total{%s} %d\n", labels, value.count)
		for i, bucket := range requestBuckets {
			bucketLabels := labels + `,le="` + strconv.FormatFloat(bucket, 'f', -1, 64) + `"`
			_, _ = fmt.Fprintf(w, "kordex_http_server_request_duration_seconds_bucket{%s} %d\n", bucketLabels, value.buckets[i])
		}
		_, _ = fmt.Fprintf(w, "kordex_http_server_request_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, value.count)
		_, _ = fmt.Fprintf(w, "kordex_http_server_request_duration_seconds_sum{%s} %.9f\n", labels, value.sum)
		_, _ = fmt.Fprintf(w, "kordex_http_server_request_duration_seconds_count{%s} %d\n", labels, value.count)
	}
	if other.count > 0 {
		labels := `method="OTHER",route="other",status="0"`
		_, _ = fmt.Fprintf(w, "kordex_http_server_requests_total{%s} %d\n", labels, other.count)
		for i, bucket := range requestBuckets {
			bucketLabels := labels + `,le="` + strconv.FormatFloat(bucket, 'f', -1, 64) + `"`
			_, _ = fmt.Fprintf(w, "kordex_http_server_request_duration_seconds_bucket{%s} %d\n", bucketLabels, other.buckets[i])
		}
		_, _ = fmt.Fprintf(w, "kordex_http_server_request_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, other.count)
		_, _ = fmt.Fprintf(w, "kordex_http_server_request_duration_seconds_sum{%s} %.9f\n", labels, other.sum)
		_, _ = fmt.Fprintf(w, "kordex_http_server_request_duration_seconds_count{%s} %d\n", labels, other.count)
	}
}

// metricsSource lets the API run metrics on a separate, independently bound listener.
type metricsSource interface{ MetricsHandler() http.Handler }

type handlerWithMetrics struct {
	http.Handler
	metrics *httpMetrics
}

func (h *handlerWithMetrics) MetricsHandler() http.Handler {
	return http.HandlerFunc(h.metrics.serveHTTP)
}

func MetricsHandler(handler http.Handler) http.Handler {
	if source, ok := handler.(metricsSource); ok {
		return source.MetricsHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
	})
}
