package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, code string, message string) {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	var got errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if got.Error.Code != code {
		t.Fatalf("error code = %q, want %q", got.Error.Code, code)
	}
	if got.Error.Message != message {
		t.Fatalf("error message = %q, want %q", got.Error.Message, message)
	}
}
