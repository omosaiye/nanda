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
	"github.com/solai/nanda/internal/registration"
)

func TestRegisterAgentHandlerSuccess(t *testing.T) {
	service := &fakeRegistrationService{
		response: registration.RegisterResponse{
			AgentID:               "agent.example",
			FactsPointer:          "fs:ab/cd/agent.facts",
			FactsPtrHash128:       "00112233445566778899aabbccddeeff",
			CredentialSet128:      "e3b0c44298fc1c149afbf4c8996fb924",
			Sequence:              7,
			TTLSeconds:            300,
			AgentAddrRecordBase64: "record",
		},
	}
	handler := RegisterAgentHandler(service)
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/register", strings.NewReader(`{
		"agentId": "agent.example",
		"ttlSeconds": 300,
		"sequence": 7,
		"facts": {"endpoint": "https://agent.example"}
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
		t.Fatal("registration service was not called")
	}
	if service.request.AgentID != "agent.example" {
		t.Fatalf("request agent id = %q, want agent.example", service.request.AgentID)
	}

	var got registration.RegisterResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got != service.response {
		t.Fatalf("response = %+v, want %+v", got, service.response)
	}
}

func TestRegisterAgentHandlerValidationFailure(t *testing.T) {
	service := &fakeRegistrationService{
		err: registration.ValidationError{Field: "agentId", Err: agentaddr.ErrEmptyAgentID},
	}
	handler := RegisterAgentHandler(service)
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/register", strings.NewReader(`{
		"ttlSeconds": 300,
		"sequence": 7,
		"facts": {}
	}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertJSONError(t, rec, "registration_validation_failed", "registration validation failed: agentId: agent id is empty")
}

func TestRegisterAgentHandlerRejectsTrailingJSON(t *testing.T) {
	service := &fakeRegistrationService{}
	handler := RegisterAgentHandler(service)
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/register", strings.NewReader(`{
		"agentId": "agent.example",
		"ttlSeconds": 300,
		"sequence": 7,
		"facts": {}
	} {}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertJSONError(t, rec, "invalid_registration_request", "invalid registration request")
	if service.called {
		t.Fatal("registration service was called")
	}
}

func TestRegisterAgentHandlerRejectsNonPost(t *testing.T) {
	handler := RegisterAgentHandler(&fakeRegistrationService{})
	req := httptest.NewRequest(http.MethodGet, "/v1/agents/register", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	assertJSONError(t, rec, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed))
}

func TestRegisterAgentHandlerInternalFailure(t *testing.T) {
	handler := RegisterAgentHandler(&fakeRegistrationService{err: errors.New("store failed")})
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/register", strings.NewReader(`{
		"agentId": "agent.example",
		"ttlSeconds": 300,
		"sequence": 7,
		"facts": {}
	}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	assertJSONError(t, rec, "internal_error", http.StatusText(http.StatusInternalServerError))
}

func TestRegisterAgentHandlerSetsRequestIDHeader(t *testing.T) {
	handler := RegisterAgentHandler(&fakeRegistrationService{})
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/register", strings.NewReader(`{
		"ttlSeconds": 300,
		"sequence": 7,
		"facts": {}
	}`))
	req.Header.Set("X-Request-ID", "register-test")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != "register-test" {
		t.Fatalf("request id header = %q, want register-test", got)
	}
}

type fakeRegistrationService struct {
	called   bool
	request  registration.RegisterRequest
	response registration.RegisterResponse
	err      error
}

func (s *fakeRegistrationService) Register(_ context.Context, req registration.RegisterRequest) (registration.RegisterResponse, error) {
	s.called = true
	s.request = req
	if s.err != nil {
		return registration.RegisterResponse{}, s.err
	}
	return s.response, nil
}
