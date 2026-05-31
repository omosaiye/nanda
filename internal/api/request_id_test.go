package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithRequestIDUsesIncomingHeader(t *testing.T) {
	handler := WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := RequestID(r); got != "req-123" {
			t.Fatalf("request id = %q, want req-123", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "req-123")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != "req-123" {
		t.Fatalf("response request id = %q, want req-123", got)
	}
}

func TestWithRequestIDGeneratesMissingHeader(t *testing.T) {
	var handlerRequestID string
	handler := WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerRequestID = RequestID(r)
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if handlerRequestID == "" {
		t.Fatal("handler request id is empty")
	}
	if got := rec.Header().Get("X-Request-ID"); got != handlerRequestID {
		t.Fatalf("response request id = %q, want %q", got, handlerRequestID)
	}
}
