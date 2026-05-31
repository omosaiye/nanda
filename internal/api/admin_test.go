package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/solai/nanda/internal/admin"
	"github.com/solai/nanda/internal/audit"
	"github.com/solai/nanda/internal/revocation"
)

func TestAdminGetAgentHandlerSuccess(t *testing.T) {
	service := &fakeAdminService{
		agent: admin.AgentResponse{
			AgentID:          "agent.example",
			AgentHash:        "abcd",
			Sequence:         7,
			TTLSeconds:       60,
			FactsPtrHash128:  "facts",
			CredentialSet128: "creds",
			RecordBase64:     "record",
		},
	}
	handler := AdminGetAgentHandler(service)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/agents/agent.example", nil)
	req.SetPathValue("agentId", "agent.example")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if service.agentID != "agent.example" {
		t.Fatalf("agent id = %q, want agent.example", service.agentID)
	}
	var got admin.AgentResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got != service.agent {
		t.Fatalf("response = %+v, want %+v", got, service.agent)
	}
}

func TestAdminGetAgentHandlerErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "validation",
			err:        admin.ValidationError{Field: "agentId", Err: errors.New("agent id is empty")},
			wantStatus: http.StatusBadRequest,
			wantCode:   "admin_validation_failed",
		},
		{
			name:       "not found",
			err:        admin.ErrNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   "not_found",
		},
		{
			name:       "internal",
			err:        errors.New("boom"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "internal_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := AdminGetAgentHandler(&fakeAdminService{err: tt.err})
			req := httptest.NewRequest(http.MethodGet, "/v1/admin/agents/agent.example", nil)
			req.SetPathValue("agentId", "agent.example")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", rec.Code, tt.wantStatus, rec.Body.String())
			}
			var got errorResponse
			if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if got.Error.Code != tt.wantCode {
				t.Fatalf("error code = %q, want %q", got.Error.Code, tt.wantCode)
			}
		})
	}
}

func TestAdminListAuditHandlerSuccess(t *testing.T) {
	service := &fakeAdminService{
		events: []audit.Event{{EventID: "event-1", AgentID: "agent.example"}},
	}
	handler := AdminListAuditHandler(service)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !service.listAuditCalled {
		t.Fatal("ListAudit was not called")
	}
	var got []audit.Event
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 || got[0].EventID != "event-1" {
		t.Fatalf("events = %+v, want event-1", got)
	}
}

func TestAdminListAuditByAgentHandlerSuccess(t *testing.T) {
	service := &fakeAdminService{
		events: []audit.Event{{EventID: "event-1", AgentID: "agent.example"}},
	}
	handler := AdminListAuditByAgentHandler(service)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit/agent.example", nil)
	req.SetPathValue("agentId", "agent.example")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if service.agentID != "agent.example" {
		t.Fatalf("agent id = %q, want agent.example", service.agentID)
	}
}

func TestAdminGetRevocationStatusHandlerSuccess(t *testing.T) {
	updatedAt := time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	service := &fakeAdminService{
		revocation: admin.RevocationStatusResponse{
			Issuer:       "issuer.example",
			CredentialID: "credential-1",
			Status:       revocation.StatusRevoked,
			Found:        true,
			UpdatedAt:    &updatedAt,
		},
	}
	handler := AdminGetRevocationStatusHandler(service)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/revocation/issuer.example/credential-1", nil)
	req.SetPathValue("issuer", "issuer.example")
	req.SetPathValue("credentialId", "credential-1")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if service.issuer != "issuer.example" || service.credentialID != "credential-1" {
		t.Fatalf("revocation key = %q/%q, want issuer.example/credential-1", service.issuer, service.credentialID)
	}
	var got admin.RevocationStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Found || got.Status != revocation.StatusRevoked {
		t.Fatalf("response = %+v, want found revoked", got)
	}
}

func TestAdminHandlersRejectWrongMethod(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		path    string
	}{
		{name: "agent", handler: AdminGetAgentHandler(&fakeAdminService{}), path: "/v1/admin/agents/agent.example"},
		{name: "audit", handler: AdminListAuditHandler(&fakeAdminService{}), path: "/v1/admin/audit"},
		{name: "audit by agent", handler: AdminListAuditByAgentHandler(&fakeAdminService{}), path: "/v1/admin/audit/agent.example"},
		{name: "revocation", handler: AdminGetRevocationStatusHandler(&fakeAdminService{}), path: "/v1/admin/revocation/issuer.example/credential-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			rec := httptest.NewRecorder()

			tt.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
			}
			assertJSONError(t, rec, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed))
		})
	}
}

func TestAdminHandlerSetsRequestIDHeader(t *testing.T) {
	handler := AdminListAuditHandler(&fakeAdminService{})
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit", nil)
	req.Header.Set("X-Request-ID", "admin-test")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != "admin-test" {
		t.Fatalf("request id header = %q, want admin-test", got)
	}
}

type fakeAdminService struct {
	agent           admin.AgentResponse
	events          []audit.Event
	revocation      admin.RevocationStatusResponse
	err             error
	agentID         string
	issuer          string
	credentialID    string
	listAuditCalled bool
}

func (s *fakeAdminService) GetAgent(_ context.Context, agentID string) (admin.AgentResponse, error) {
	s.agentID = agentID
	if s.err != nil {
		return admin.AgentResponse{}, s.err
	}
	return s.agent, nil
}

func (s *fakeAdminService) ListAudit(_ context.Context) ([]audit.Event, error) {
	s.listAuditCalled = true
	if s.err != nil {
		return nil, s.err
	}
	return s.events, nil
}

func (s *fakeAdminService) ListAuditByAgent(_ context.Context, agentID string) ([]audit.Event, error) {
	s.agentID = agentID
	if s.err != nil {
		return nil, s.err
	}
	return s.events, nil
}

func (s *fakeAdminService) GetRevocationStatus(_ context.Context, issuer string, credentialID string) (admin.RevocationStatusResponse, error) {
	s.issuer = issuer
	s.credentialID = credentialID
	if s.err != nil {
		return admin.RevocationStatusResponse{}, s.err
	}
	return s.revocation, nil
}
