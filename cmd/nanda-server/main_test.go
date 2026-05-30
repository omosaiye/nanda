package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeHandlers(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus string
	}{
		{
			name:       "healthz",
			handler:    healthzHandler,
			wantStatus: "ok",
		},
		{
			name:       "readyz",
			handler:    readyzHandler,
			wantStatus: "ready",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/"+tt.name, nil)
			response := httptest.NewRecorder()

			tt.handler(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status code = %d, want %d", response.Code, http.StatusOK)
			}
			if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
				t.Fatalf("content type = %q, want %q", contentType, "application/json")
			}

			var compactBody bytes.Buffer
			if err := json.Compact(&compactBody, response.Body.Bytes()); err != nil {
				t.Fatalf("compact response JSON: %v", err)
			}
			wantBody := `{"status":"` + tt.wantStatus + `"}`
			if compactBody.String() != wantBody {
				t.Fatalf("response body = %q, want %q", compactBody.String(), wantBody)
			}
		})
	}
}
