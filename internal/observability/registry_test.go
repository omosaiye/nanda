package observability

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestCountersIncrementCorrectly(t *testing.T) {
	registry := NewRegistry()

	registry.IncHTTPRequests("POST", RouteResolve, 200)
	registry.IncHTTPRequests("POST", RouteResolve, 200)
	registry.IncResolveRequests("allowed", 200)
	registry.IncTrustDenied()
	registry.IncAuditEvents("resolve.allowed", "allowed")

	metrics := renderMetrics(t, registry)

	assertContains(t, metrics, `nanda_http_requests_total{method="POST",route="/v1/resolve",status="200"} 2`)
	assertContains(t, metrics, `nanda_resolve_requests_total{decision="allowed",status="200"} 1`)
	assertContains(t, metrics, `nanda_trust_denied_total 1`)
	assertContains(t, metrics, `nanda_audit_events_total{decision="allowed",eventType="resolve.allowed"} 1`)
}

func TestLatencyObservationsAreRecorded(t *testing.T) {
	registry := NewRegistry()

	registry.ObserveHTTPRequest(RouteResolve, 10*time.Millisecond)
	registry.ObserveHTTPRequest(RouteResolve, 25*time.Millisecond)

	metrics := renderMetrics(t, registry)

	assertContains(t, metrics, `nanda_http_request_duration_ms_count{route="/v1/resolve"} 2`)
	assertContains(t, metrics, `nanda_http_request_duration_ms_sum{route="/v1/resolve"} 35.000`)
	assertContains(t, metrics, `nanda_http_request_duration_ms_min{route="/v1/resolve"} 10.000`)
	assertContains(t, metrics, `nanda_http_request_duration_ms_max{route="/v1/resolve"} 25.000`)
}

func TestRenderedMetricsDoNotIncludeHighCardinalityPathValues(t *testing.T) {
	registry := NewRegistry()

	registry.IncHTTPRequests("GET", "/v1/admin/agents/agent.example", 200)
	registry.ObserveHTTPRequest("/v1/admin/revocation/did:example:issuer/credential-1", time.Millisecond)

	metrics := renderMetrics(t, registry)

	assertContains(t, metrics, `route="/v1/admin/agents/{agentId}"`)
	assertContains(t, metrics, `route="/v1/admin/revocation/{issuer}/{credentialId}"`)
	if strings.Contains(metrics, "agent.example") {
		t.Fatalf("metrics include agent id: %s", metrics)
	}
	if strings.Contains(metrics, "did:example:issuer") || strings.Contains(metrics, "credential-1") {
		t.Fatalf("metrics include revocation path values: %s", metrics)
	}
}

func renderMetrics(t *testing.T, registry *Registry) string {
	t.Helper()

	var body bytes.Buffer
	if err := registry.Render(&body); err != nil {
		t.Fatalf("render metrics: %v", err)
	}
	return body.String()
}

func assertContains(t *testing.T, got string, want string) {
	t.Helper()

	if !strings.Contains(got, want) {
		t.Fatalf("metrics = %q, want to contain %q", got, want)
	}
}
