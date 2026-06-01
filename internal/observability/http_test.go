package observability

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddlewareRecordsRouteAndStatus(t *testing.T) {
	registry := NewRegistry()
	mux := http.NewServeMux()
	mux.HandleFunc(RouteResolve, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	handler := Middleware(registry, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), mux)

	request := httptest.NewRequest(http.MethodPost, RouteResolve, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	metrics := renderMetrics(t, registry)
	assertContains(t, metrics, `nanda_http_requests_total{method="POST",route="/v1/resolve",status="202"} 1`)
	assertContains(t, metrics, `nanda_resolve_requests_total{decision="allowed",status="202"} 1`)
	assertContains(t, metrics, `nanda_http_request_duration_ms_count{route="/v1/resolve"} 1`)
}

func TestMiddlewareLogsRequestWithoutSecrets(t *testing.T) {
	var logs bytes.Buffer
	registry := NewRegistry()
	mux := http.NewServeMux()
	mux.HandleFunc(RouteRegister, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	handler := Middleware(registry, slog.New(slog.NewTextHandler(&logs, nil)), mux)

	request := httptest.NewRequest(http.MethodPost, RouteRegister, strings.NewReader(`{"secret":"body"}`))
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Request-ID", "test-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	got := logs.String()
	assertContains(t, got, "request_id=test-request")
	assertContains(t, got, "method=POST")
	assertContains(t, got, `route=/v1/agents/register`)
	assertContains(t, got, "status=201")
	if strings.Contains(got, "Authorization") || strings.Contains(got, "Bearer secret") || strings.Contains(got, "body") {
		t.Fatalf("log includes sensitive request data: %s", got)
	}
}
