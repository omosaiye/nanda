package observability

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

const requestIDHeader = "X-Request-ID"

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
		r.ResponseWriter.WriteHeader(status)
	}
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(data)
}

func Middleware(registry *Registry, logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &responseRecorder{ResponseWriter: w}

		next.ServeHTTP(recorder, r)

		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		route := RouteForRequest(r)
		duration := time.Since(start)
		durationMS := float64(duration.Microseconds()) / 1000

		if registry != nil {
			registry.IncHTTPRequests(r.Method, route, status)
			registry.ObserveHTTPRequest(route, duration)
			recordRouteMetrics(registry, r.Method, route, status)
		}

		requestID := r.Header.Get(requestIDHeader)
		if requestID == "" {
			requestID = recorder.Header().Get(requestIDHeader)
		}
		logger.Info("http_request",
			"request_id", requestID,
			"method", r.Method,
			"route", route,
			"status", status,
			"duration_ms", strconv.FormatFloat(durationMS, 'f', 3, 64),
		)
	})
}

func recordRouteMetrics(registry *Registry, method string, route string, status int) {
	switch route {
	case RouteRegister:
		registry.IncRegistrationRequests(requestDecision(status), status)
	case RouteResolve:
		decision := resolveDecision(status)
		registry.IncResolveRequests(decision, status)
		if status == http.StatusForbidden {
			registry.IncTrustDenied()
		}
	case RouteAdminAgent, RouteAdminAudit, RouteAdminAuditAgent, RouteAdminRevocation, RouteAdminRevokedID:
		registry.IncAdminRequests(route, status)
		if route == RouteAdminRevocation && method == http.MethodPost && status >= 200 && status < 300 {
			registry.IncRevocationUpdates()
		}
	}
}

func requestDecision(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "allowed"
	case status >= 500:
		return "error"
	default:
		return "denied"
	}
}

func resolveDecision(status int) string {
	switch status {
	case http.StatusNotFound:
		return "not_found"
	case http.StatusGone:
		return "expired"
	default:
		return requestDecision(status)
	}
}
