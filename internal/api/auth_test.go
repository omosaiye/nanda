package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithBearerAuthRejectsMissingTokenWhenEnabled(t *testing.T) {
	handler := WithBearerAuth(okHandler(), "secret")
	request := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertUnauthorized(t, response)
}

func TestWithBearerAuthRejectsWrongToken(t *testing.T) {
	handler := WithBearerAuth(okHandler(), "secret")
	request := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
	request.Header.Set("Authorization", "Bearer wrong")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertUnauthorized(t, response)
}

func TestWithBearerAuthAcceptsCorrectToken(t *testing.T) {
	handler := WithBearerAuth(okHandler(), "secret")
	request := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestWithBearerAuthDisabledWithoutToken(t *testing.T) {
	handler := WithBearerAuth(okHandler(), "")
	request := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func assertUnauthorized(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("content type = %q, want application/json", contentType)
	}
	var compactBody bytes.Buffer
	if err := json.Compact(&compactBody, response.Body.Bytes()); err != nil {
		t.Fatalf("compact response JSON: %v", err)
	}
	wantBody := `{"error":{"code":"unauthorized","message":"Unauthorized"}}`
	if compactBody.String() != wantBody {
		t.Fatalf("response body = %q, want %q", compactBody.String(), wantBody)
	}
}
