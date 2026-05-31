package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/agentfacts"
	"github.com/solai/nanda/internal/resolver"
)

func TestResolveAgentHandlerSuccess(t *testing.T) {
	service := &fakeResolverService{
		response: resolver.ResolveResponse{
			AgentID: "agent.example",
			Endpoint: agentfacts.Endpoint{
				ID:         "static",
				Type:       "static",
				URL:        "https://agent.example",
				Protocol:   "https",
				TTLSeconds: 60,
			},
			TrustDecision: resolver.TrustDecisionUnverifiedV0,
			ProofBundle: resolver.ProofBundle{
				AgentAddrSignatureVerified:    true,
				AgentFactsPointerHashVerified: true,
				AgentFactsSchemaVerified:      true,
				CredentialStatus:              resolver.CredentialStatusNotImplemented,
			},
		},
	}
	handler := ResolveAgentHandler(service)
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(`{
		"agentId": "agent.example",
		"requiredCapability": "chat"
	}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	if !service.called {
		t.Fatal("resolver service was not called")
	}
	if service.request.AgentID != "agent.example" {
		t.Fatalf("request agent id = %q, want agent.example", service.request.AgentID)
	}
	if service.request.RequiredCapability != "chat" {
		t.Fatalf("required capability = %q, want chat", service.request.RequiredCapability)
	}

	var got resolver.ResolveResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.AgentID != service.response.AgentID || got.Endpoint != service.response.Endpoint || got.TrustDecision != service.response.TrustDecision || got.ProofBundle != service.response.ProofBundle {
		t.Fatalf("response = %+v, want %+v", got, service.response)
	}
}

func TestResolveAgentHandlerValidationFailure(t *testing.T) {
	service := &fakeResolverService{
		err: resolver.ValidationError{Field: "agentId", Err: agentaddr.ErrEmptyAgentID},
	}
	handler := ResolveAgentHandler(service)
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(`{
		"agentId": ""
	}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestResolveAgentHandlerNotFound(t *testing.T) {
	service := &fakeResolverService{err: resolver.ErrNotFound}
	handler := ResolveAgentHandler(service)
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(`{
		"agentId": "agent.example"
	}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestResolveAgentHandlerTrustDenied(t *testing.T) {
	service := &fakeResolverService{err: resolver.ErrTrustDenied}
	handler := ResolveAgentHandler(service)
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(`{
		"agentId": "agent.example",
		"requiredCapability": "chat"
	}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestResolveAgentHandlerRejectsNonPost(t *testing.T) {
	handler := ResolveAgentHandler(&fakeResolverService{})
	req := httptest.NewRequest(http.MethodGet, "/v1/resolve", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestResolveAgentHandlerRejectsMalformedUnknownAndTrailingJSON(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed", body: `{"agentId":`},
		{name: "unknown field", body: `{"agentId":"agent.example","unknown":true}`},
		{name: "trailing json", body: `{"agentId":"agent.example"} {}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &fakeResolverService{}
			handler := ResolveAgentHandler(service)
			req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if service.called {
				t.Fatal("resolver service was called")
			}
		})
	}
}

func TestResolveAgentHandlerInternalFailure(t *testing.T) {
	handler := ResolveAgentHandler(&fakeResolverService{err: errors.New("boom")})
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(`{
		"agentId": "agent.example"
	}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

type fakeResolverService struct {
	called   bool
	request  resolver.ResolveRequest
	response resolver.ResolveResponse
	err      error
}

func (s *fakeResolverService) Resolve(_ context.Context, req resolver.ResolveRequest) (resolver.ResolveResponse, error) {
	s.called = true
	s.request = req
	if s.err != nil {
		return resolver.ResolveResponse{}, s.err
	}
	return s.response, nil
}
