package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
		auditResult: audit.ListResult{
			Items:  []audit.Event{{EventID: "event-1", AgentID: "agent.example"}},
			Limit:  1,
			Offset: 0,
			Count:  1,
		},
	}
	handler := AdminListAuditHandler(service)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit?limit=1&offset=0", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !service.listAuditCalled {
		t.Fatal("ListAudit was not called")
	}
	if service.auditQuery.Limit != 1 || service.auditQuery.Offset != 0 {
		t.Fatalf("query = %+v, want limit 1 offset 0", service.auditQuery)
	}
	var got audit.ListResult
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Limit != 1 || got.Offset != 0 || got.Count != 1 {
		t.Fatalf("page = %+v, want limit 1 offset 0 count 1", got)
	}
	if len(got.Items) != 1 || got.Items[0].EventID != "event-1" {
		t.Fatalf("events = %+v, want event-1", got.Items)
	}
}

func TestAdminListAuditByAgentHandlerSuccess(t *testing.T) {
	service := &fakeAdminService{
		auditResult: audit.ListResult{
			Items:  []audit.Event{{EventID: "event-1", AgentID: "agent.example", EventType: audit.EventResolveAllowed, Decision: audit.DecisionAllowed}},
			Limit:  audit.DefaultListLimit,
			Offset: 0,
			Count:  1,
		},
	}
	handler := AdminListAuditByAgentHandler(service)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit/agent.example?eventType=resolve.allowed&decision=allowed", nil)
	req.SetPathValue("agentId", "agent.example")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if service.agentID != "agent.example" {
		t.Fatalf("agent id = %q, want agent.example", service.agentID)
	}
	if service.auditQuery.EventType != audit.EventResolveAllowed || service.auditQuery.Decision != audit.DecisionAllowed {
		t.Fatalf("query = %+v, want resolve.allowed/allowed", service.auditQuery)
	}
	var got audit.ListResult
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Count != 1 || len(got.Items) != 1 || got.Items[0].EventID != "event-1" {
		t.Fatalf("response = %+v, want event-1", got)
	}
}

func TestAdminListAuditHandlerInvalidQuery(t *testing.T) {
	handler := AdminListAuditHandler(&fakeAdminService{})
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit?limit=not-an-int", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertJSONError(t, rec, "admin_validation_failed", "admin validation failed: limit: limit must be a positive integer")
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

func TestAdminSetRevocationStatusHandlerSuccess(t *testing.T) {
	service := &fakeAdminService{
		setRevocationResponse: admin.SetRevocationStatusResponse{
			Issuer:       "did:example:issuer",
			CredentialID: "credential-1",
			Status:       revocation.StatusRevoked,
			Reason:       "operator action",
			Updated:      true,
		},
	}
	handler := AdminSetRevocationStatusHandler(service)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/revocation", strings.NewReader(`{
		"issuer":"did:example:issuer",
		"credentialId":"credential-1",
		"status":"revoked",
		"reason":"operator action"
	}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if service.setRevocationRequest.Issuer != "did:example:issuer" || service.setRevocationRequest.CredentialID != "credential-1" || service.setRevocationRequest.Status != revocation.StatusRevoked || service.setRevocationRequest.Reason != "operator action" {
		t.Fatalf("request = %+v, want revocation request", service.setRevocationRequest)
	}
	var got admin.SetRevocationStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got != service.setRevocationResponse {
		t.Fatalf("response = %+v, want %+v", got, service.setRevocationResponse)
	}
}

func TestAdminSetRevocationStatusHandlerMalformedJSON(t *testing.T) {
	handler := AdminSetRevocationStatusHandler(&fakeAdminService{})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/revocation", strings.NewReader(`{"issuer":`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertJSONError(t, rec, "invalid_json", "request body must be valid JSON")
}

func TestAdminSetRevocationStatusHandlerInvalidBody(t *testing.T) {
	handler := AdminSetRevocationStatusHandler(&fakeAdminService{
		err: admin.ValidationError{Field: "status", Err: errors.New("status must be active or revoked")},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/revocation", strings.NewReader(`{"issuer":"did:example:issuer","credentialId":"credential-1","status":"disabled"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertJSONError(t, rec, "admin_validation_failed", "admin validation failed: status: status must be active or revoked")
}

func TestAdminHandlersRejectWrongMethod(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		path    string
		method  string
	}{
		{name: "agent", handler: AdminGetAgentHandler(&fakeAdminService{}), path: "/v1/admin/agents/agent.example", method: http.MethodPost},
		{name: "audit", handler: AdminListAuditHandler(&fakeAdminService{}), path: "/v1/admin/audit", method: http.MethodPost},
		{name: "audit by agent", handler: AdminListAuditByAgentHandler(&fakeAdminService{}), path: "/v1/admin/audit/agent.example", method: http.MethodPost},
		{name: "revocation", handler: AdminGetRevocationStatusHandler(&fakeAdminService{}), path: "/v1/admin/revocation/issuer.example/credential-1", method: http.MethodPost},
		{name: "set revocation", handler: AdminSetRevocationStatusHandler(&fakeAdminService{}), path: "/v1/admin/revocation", method: http.MethodGet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
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

func TestAdminSetRevocationStatusHandlerSetsRequestIDHeader(t *testing.T) {
	handler := AdminSetRevocationStatusHandler(&fakeAdminService{
		setRevocationResponse: admin.SetRevocationStatusResponse{
			Issuer:       "did:example:issuer",
			CredentialID: "credential-1",
			Status:       revocation.StatusRevoked,
			Updated:      true,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/revocation", strings.NewReader(`{"issuer":"did:example:issuer","credentialId":"credential-1","status":"revoked"}`))
	req.Header.Set("X-Request-ID", "admin-revocation-test")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != "admin-revocation-test" {
		t.Fatalf("request id header = %q, want admin-revocation-test", got)
	}
}

type fakeAdminService struct {
	agent                 admin.AgentResponse
	auditResult           audit.ListResult
	revocation            admin.RevocationStatusResponse
	setRevocationResponse admin.SetRevocationStatusResponse
	err                   error
	agentID               string
	issuer                string
	credentialID          string
	setRevocationRequest  admin.SetRevocationStatusRequest
	listAuditCalled       bool
	auditQuery            audit.Query
}

func (s *fakeAdminService) GetAgent(_ context.Context, agentID string) (admin.AgentResponse, error) {
	s.agentID = agentID
	if s.err != nil {
		return admin.AgentResponse{}, s.err
	}
	return s.agent, nil
}

func (s *fakeAdminService) ListAudit(_ context.Context, query audit.Query) (audit.ListResult, error) {
	s.listAuditCalled = true
	s.auditQuery = query
	if s.err != nil {
		return audit.ListResult{}, s.err
	}
	return s.auditResult, nil
}

func (s *fakeAdminService) ListAuditByAgent(_ context.Context, agentID string, query audit.Query) (audit.ListResult, error) {
	s.agentID = agentID
	s.auditQuery = query
	if s.err != nil {
		return audit.ListResult{}, s.err
	}
	return s.auditResult, nil
}

func (s *fakeAdminService) GetRevocationStatus(_ context.Context, issuer string, credentialID string) (admin.RevocationStatusResponse, error) {
	s.issuer = issuer
	s.credentialID = credentialID
	if s.err != nil {
		return admin.RevocationStatusResponse{}, s.err
	}
	return s.revocation, nil
}

func (s *fakeAdminService) SetRevocationStatus(_ context.Context, req admin.SetRevocationStatusRequest) (admin.SetRevocationStatusResponse, error) {
	s.setRevocationRequest = req
	if s.err != nil {
		return admin.SetRevocationStatusResponse{}, s.err
	}
	return s.setRevocationResponse, nil
}
