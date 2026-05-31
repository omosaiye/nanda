package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSONError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	WriteJSONError(rec, req, http.StatusForbidden, "trust_denied", "resolve trust denied")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	var got errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if got.Error.Code != "trust_denied" {
		t.Fatalf("code = %q, want trust_denied", got.Error.Code)
	}
	if got.Error.Message != "resolve trust denied" {
		t.Fatalf("message = %q, want resolve trust denied", got.Error.Message)
	}
}
