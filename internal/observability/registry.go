package observability

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	RouteUnknown         = "unknown"
	RouteHealthz         = "/healthz"
	RouteReadyz          = "/readyz"
	RouteMetrics         = "/metrics"
	RouteRegister        = "/v1/agents/register"
	RouteResolve         = "/v1/resolve"
	RouteAdminAgent      = "/v1/admin/agents/{agentId}"
	RouteAdminAudit      = "/v1/admin/audit"
	RouteAdminAuditAgent = "/v1/admin/audit/{agentId}"
	RouteAdminRevocation = "/v1/admin/revocation"
	RouteAdminRevokedID  = "/v1/admin/revocation/{issuer}/{credentialId}"
)

type Registry struct {
	mu        sync.Mutex
	counters  map[metricKey]uint64
	latencies map[metricKey]latencyStats
}

type metricKey struct {
	name   string
	labels string
}

type latencyStats struct {
	Count uint64
	Sum   float64
	Min   float64
	Max   float64
}

func NewRegistry() *Registry {
	return &Registry{
		counters:  make(map[metricKey]uint64),
		latencies: make(map[metricKey]latencyStats),
	}
}

func (r *Registry) IncHTTPRequests(method string, route string, status int) {
	r.addCounter("nanda_http_requests_total", map[string]string{
		"method": method,
		"route":  safeRoute(route),
		"status": strconv.Itoa(status),
	}, 1)
}

func (r *Registry) ObserveHTTPRequest(route string, duration time.Duration) {
	ms := float64(duration.Microseconds()) / 1000
	r.observeLatency("nanda_http_request_duration_ms", map[string]string{
		"route": safeRoute(route),
	}, ms)
}

func (r *Registry) IncRegistrationRequests(decision string, status int) {
	r.addCounter("nanda_registration_requests_total", map[string]string{
		"decision": decision,
		"status":   strconv.Itoa(status),
	}, 1)
}

func (r *Registry) IncResolveRequests(decision string, status int) {
	r.addCounter("nanda_resolve_requests_total", map[string]string{
		"decision": decision,
		"status":   strconv.Itoa(status),
	}, 1)
}

func (r *Registry) IncAdminRequests(route string, status int) {
	r.addCounter("nanda_admin_requests_total", map[string]string{
		"route":  safeRoute(route),
		"status": strconv.Itoa(status),
	}, 1)
}

func (r *Registry) IncTrustDenied() {
	r.addCounter("nanda_trust_denied_total", nil, 1)
}

func (r *Registry) IncRevocationUpdates() {
	r.addCounter("nanda_revocation_updates_total", nil, 1)
}

func (r *Registry) IncAuditEvents(eventType string, decision string) {
	r.addCounter("nanda_audit_events_total", map[string]string{
		"eventType": eventType,
		"decision":  decision,
	}, 1)
}

func (r *Registry) Render(w io.Writer) error {
	r.mu.Lock()
	counters := make([]counterSample, 0, len(r.counters))
	for key, value := range r.counters {
		counters = append(counters, counterSample{key: key, value: value})
	}
	latencies := make([]latencySample, 0, len(r.latencies))
	for key, value := range r.latencies {
		latencies = append(latencies, latencySample{key: key, value: value})
	}
	r.mu.Unlock()

	sort.Slice(counters, func(i, j int) bool {
		return sampleLess(counters[i].key, counters[j].key)
	})
	sort.Slice(latencies, func(i, j int) bool {
		return sampleLess(latencies[i].key, latencies[j].key)
	})

	for _, sample := range counters {
		if _, err := fmt.Fprintf(w, "%s%s %d\n", sample.key.name, sample.key.labels, sample.value); err != nil {
			return err
		}
	}
	for _, sample := range latencies {
		if _, err := fmt.Fprintf(w, "%s_count%s %d\n", sample.key.name, sample.key.labels, sample.value.Count); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_sum%s %.3f\n", sample.key.name, sample.key.labels, sample.value.Sum); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_min%s %.3f\n", sample.key.name, sample.key.labels, sample.value.Min); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_max%s %.3f\n", sample.key.name, sample.key.labels, sample.value.Max); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) addCounter(name string, labels map[string]string, delta uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[metricKey{name: name, labels: formatLabels(labels)}] += delta
}

func (r *Registry) observeLatency(name string, labels map[string]string, value float64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := metricKey{name: name, labels: formatLabels(labels)}
	stats := r.latencies[key]
	stats.Count++
	stats.Sum += value
	if stats.Count == 1 || value < stats.Min {
		stats.Min = value
	}
	if stats.Count == 1 || value > stats.Max {
		stats.Max = value
	}
	r.latencies[key] = stats
}

func ClassifyRoute(path string) string {
	switch path {
	case RouteHealthz, RouteReadyz, RouteMetrics, RouteRegister, RouteResolve, RouteAdminAudit, RouteAdminRevocation:
		return path
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 4 && parts[0] == "v1" && parts[1] == "admin" && parts[2] == "agents" {
		return RouteAdminAgent
	}
	if len(parts) == 4 && parts[0] == "v1" && parts[1] == "admin" && parts[2] == "audit" {
		return RouteAdminAuditAgent
	}
	if len(parts) == 5 && parts[0] == "v1" && parts[1] == "admin" && parts[2] == "revocation" {
		return RouteAdminRevokedID
	}
	return RouteUnknown
}

func RouteForRequest(r *http.Request) string {
	if r == nil {
		return RouteUnknown
	}
	if r.Pattern != "" {
		return safeRoute(r.Pattern)
	}
	return ClassifyRoute(r.URL.Path)
}

func IsAdminRoute(route string) bool {
	return strings.HasPrefix(route, "/v1/admin/")
}

type counterSample struct {
	key   metricKey
	value uint64
}

type latencySample struct {
	key   metricKey
	value latencyStats
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+`="`+escapeLabel(labels[key])+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func safeRoute(route string) string {
	switch route {
	case RouteHealthz, RouteReadyz, RouteMetrics, RouteRegister, RouteResolve, RouteAdminAgent, RouteAdminAudit, RouteAdminAuditAgent, RouteAdminRevocation, RouteAdminRevokedID:
		return route
	default:
		return ClassifyRoute(route)
	}
}

func sampleLess(a metricKey, b metricKey) bool {
	if a.name != b.name {
		return a.name < b.name
	}
	return a.labels < b.labels
}
