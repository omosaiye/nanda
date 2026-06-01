package admin

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/audit"
	"github.com/solai/nanda/internal/index"
	"github.com/solai/nanda/internal/revocation"
)

func TestGetAgentSuccess(t *testing.T) {
	record := testAgentRecord(t, "agent.example")
	createdAt := time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(time.Hour)
	store := &fakeIndexStore{
		record: index.IndexedRecord{
			AgentID:   "agent.example",
			Record:    record,
			CreatedAt: createdAt,
			UpdatedAt: updatedAt,
		},
	}
	service := newTestService(t, store, audit.NewMemoryStore(), revocation.NewMemoryStore())

	resp, err := service.GetAgent(context.Background(), " Agent.Example ")
	if err != nil {
		t.Fatalf("GetAgent returned error: %v", err)
	}

	agentHash, err := agentaddr.AgentIDHash("agent.example")
	if err != nil {
		t.Fatalf("hash agent id: %v", err)
	}
	payload := record.Payload()
	if resp.AgentID != "agent.example" {
		t.Fatalf("agent id = %q, want agent.example", resp.AgentID)
	}
	if resp.AgentHash != hex.EncodeToString(agentHash[:]) {
		t.Fatalf("agent hash = %q, want %q", resp.AgentHash, hex.EncodeToString(agentHash[:]))
	}
	if resp.Sequence != payload.Sequence {
		t.Fatalf("sequence = %d, want %d", resp.Sequence, payload.Sequence)
	}
	if resp.TTLSeconds != payload.TTLSeconds {
		t.Fatalf("ttl seconds = %d, want %d", resp.TTLSeconds, payload.TTLSeconds)
	}
	if resp.FactsPtrHash128 != hex.EncodeToString(payload.FactsPtrHash128[:]) {
		t.Fatalf("facts hash = %q, want %q", resp.FactsPtrHash128, hex.EncodeToString(payload.FactsPtrHash128[:]))
	}
	if resp.CredentialSet128 != hex.EncodeToString(payload.CredentialSet128[:]) {
		t.Fatalf("credential set = %q, want %q", resp.CredentialSet128, hex.EncodeToString(payload.CredentialSet128[:]))
	}
	if resp.RecordBase64 != base64.StdEncoding.EncodeToString(record.Encode()) {
		t.Fatalf("record base64 = %q, want %q", resp.RecordBase64, base64.StdEncoding.EncodeToString(record.Encode()))
	}
	if resp.CreatedAt != createdAt.Format(time.RFC3339) {
		t.Fatalf("createdAt = %q, want %q", resp.CreatedAt, createdAt.Format(time.RFC3339))
	}
	if resp.UpdatedAt != updatedAt.Format(time.RFC3339) {
		t.Fatalf("updatedAt = %q, want %q", resp.UpdatedAt, updatedAt.Format(time.RFC3339))
	}
	wantExpiresAt := updatedAt.Add(time.Duration(payload.TTLSeconds) * time.Second).Format(time.RFC3339)
	if resp.ExpiresAt != wantExpiresAt {
		t.Fatalf("expiresAt = %q, want %q", resp.ExpiresAt, wantExpiresAt)
	}
	if resp.Expired {
		t.Fatal("expired = true, want false")
	}
	if store.gotHash != agentHash {
		t.Fatalf("store hash = %x, want %x", store.gotHash, agentHash)
	}
}

func TestGetAgentNotFound(t *testing.T) {
	service := newTestService(t, &fakeIndexStore{err: index.ErrNotFound}, audit.NewMemoryStore(), revocation.NewMemoryStore())

	_, err := service.GetAgent(context.Background(), "missing.example")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestListAudit(t *testing.T) {
	auditStore := audit.NewMemoryStore()
	event := appendAuditEvent(t, auditStore, "agent.example")
	service := newTestService(t, &fakeIndexStore{}, auditStore, revocation.NewMemoryStore())

	result, err := service.ListAudit(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("ListAudit returned error: %v", err)
	}
	if result.Limit != audit.DefaultListLimit || result.Offset != 0 || result.Count != 1 {
		t.Fatalf("page = limit %d offset %d count %d, want %d/0/1", result.Limit, result.Offset, result.Count, audit.DefaultListLimit)
	}
	if len(result.Items) != 1 {
		t.Fatalf("event count = %d, want 1", len(result.Items))
	}
	if result.Items[0].EventID != event.EventID {
		t.Fatalf("event id = %q, want %q", result.Items[0].EventID, event.EventID)
	}
}

func TestListAuditByAgent(t *testing.T) {
	auditStore := audit.NewMemoryStore()
	want := appendAuditEvent(t, auditStore, "agent.example")
	appendAuditEvent(t, auditStore, "other.example")
	service := newTestService(t, &fakeIndexStore{}, auditStore, revocation.NewMemoryStore())

	result, err := service.ListAuditByAgent(context.Background(), " Agent.Example ", audit.Query{})
	if err != nil {
		t.Fatalf("ListAuditByAgent returned error: %v", err)
	}
	if result.Count != 1 || len(result.Items) != 1 {
		t.Fatalf("event count = %d/%d, want 1/1", result.Count, len(result.Items))
	}
	if result.Items[0].EventID != want.EventID {
		t.Fatalf("event id = %q, want %q", result.Items[0].EventID, want.EventID)
	}
}

func TestListAuditInvalidOptions(t *testing.T) {
	service := newTestService(t, &fakeIndexStore{}, audit.NewMemoryStore(), revocation.NewMemoryStore())

	_, err := service.ListAudit(context.Background(), audit.Query{EventType: "unknown"})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("ListAudit error = %v, want %v", err, ErrValidation)
	}
}

func TestGetRevocationStatusMissingReturnsActiveNotFound(t *testing.T) {
	service := newTestService(t, &fakeIndexStore{}, audit.NewMemoryStore(), revocation.NewMemoryStore())

	resp, err := service.GetRevocationStatus(context.Background(), "issuer.example", "credential-1")
	if err != nil {
		t.Fatalf("GetRevocationStatus returned error: %v", err)
	}
	if resp.Found {
		t.Fatal("found = true, want false")
	}
	if resp.Status != revocation.StatusActive {
		t.Fatalf("status = %q, want %q", resp.Status, revocation.StatusActive)
	}
	if resp.Issuer != "issuer.example" || resp.CredentialID != "credential-1" {
		t.Fatalf("response key = %q/%q, want issuer.example/credential-1", resp.Issuer, resp.CredentialID)
	}
}

func TestSetRevocationStatusSuccess(t *testing.T) {
	revocationStore := &fakeRevocationStore{}
	service := newTestService(t, &fakeIndexStore{}, audit.NewMemoryStore(), revocationStore)

	resp, err := service.SetRevocationStatus(context.Background(), SetRevocationStatusRequest{
		Issuer:       "did:example:issuer",
		CredentialID: "credential-1",
		Status:       revocation.StatusRevoked,
		Reason:       "operator action",
	})
	if err != nil {
		t.Fatalf("SetRevocationStatus returned error: %v", err)
	}
	if !resp.Updated {
		t.Fatal("updated = false, want true")
	}
	if resp.Issuer != "did:example:issuer" || resp.CredentialID != "credential-1" || resp.Status != revocation.StatusRevoked || resp.Reason != "operator action" {
		t.Fatalf("response = %+v, want revoked response", resp)
	}
	if revocationStore.setIssuer != "did:example:issuer" || revocationStore.setCredentialID != "credential-1" || revocationStore.setStatus != revocation.StatusRevoked || revocationStore.setReason != "operator action" {
		t.Fatalf("set status args = %q/%q/%q/%q", revocationStore.setIssuer, revocationStore.setCredentialID, revocationStore.setStatus, revocationStore.setReason)
	}
}

func TestSetRevocationStatusValidation(t *testing.T) {
	tests := []struct {
		name string
		req  SetRevocationStatusRequest
	}{
		{
			name: "invalid issuer",
			req: SetRevocationStatusRequest{
				CredentialID: "credential-1",
				Status:       revocation.StatusRevoked,
			},
		},
		{
			name: "invalid credential id",
			req: SetRevocationStatusRequest{
				Issuer: "did:example:issuer",
				Status: revocation.StatusRevoked,
			},
		},
		{
			name: "invalid status",
			req: SetRevocationStatusRequest{
				Issuer:       "did:example:issuer",
				CredentialID: "credential-1",
				Status:       "disabled",
			},
		},
	}

	service := newTestService(t, &fakeIndexStore{}, audit.NewMemoryStore(), revocation.NewMemoryStore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.SetRevocationStatus(context.Background(), tt.req)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("SetRevocationStatus error = %v, want ErrValidation", err)
			}
		})
	}
}

func TestSetRevocationStatusWritesAuditEvent(t *testing.T) {
	auditStore := audit.NewMemoryStore()
	service := newTestService(t, &fakeIndexStore{}, auditStore, revocation.NewMemoryStore())

	_, err := service.SetRevocationStatus(context.Background(), SetRevocationStatusRequest{
		Issuer:       "did:example:issuer",
		CredentialID: "credential-1",
		Status:       revocation.StatusRevoked,
		Reason:       "operator action",
	})
	if err != nil {
		t.Fatalf("SetRevocationStatus returned error: %v", err)
	}

	events, err := auditStore.List(context.Background())
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	event := events[0]
	if event.EventType != audit.EventRevocationUpdated {
		t.Fatalf("event type = %q, want %q", event.EventType, audit.EventRevocationUpdated)
	}
	if event.Decision != audit.DecisionAllowed {
		t.Fatalf("decision = %q, want %q", event.Decision, audit.DecisionAllowed)
	}
	var payload struct {
		Issuer       string `json:"issuer"`
		CredentialID string `json:"credentialId"`
		Status       string `json:"status"`
		Reason       string `json:"reason"`
	}
	if err := json.Unmarshal(event.EventJSON, &payload); err != nil {
		t.Fatalf("unmarshal audit payload: %v", err)
	}
	if payload.Issuer != "did:example:issuer" || payload.CredentialID != "credential-1" || payload.Status != revocation.StatusRevoked || payload.Reason != "operator action" {
		t.Fatalf("audit payload = %+v, want revocation update", payload)
	}
}

func testAgentRecord(t *testing.T, agentID string) agentaddr.AgentAddr120 {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var factsHash [16]byte
	copy(factsHash[:], []byte("facts-hash-12345"))
	var credentialSet [16]byte
	copy(credentialSet[:], []byte("credential-12345"))
	payload, err := agentaddr.New(agentID, 60, 0, 7, factsHash, credentialSet)
	if err != nil {
		t.Fatalf("new payload: %v", err)
	}
	record, err := agentaddr.Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}
	return record
}

func appendAuditEvent(t *testing.T, store audit.Store, agentID string) audit.Event {
	t.Helper()
	event, err := store.Append(context.Background(), audit.EventInput{
		EventType: audit.EventAgentRegistered,
		AgentID:   agentID,
		Decision:  audit.DecisionAllowed,
		EventJSON: []byte(`{"ok":true}`),
	})
	if err != nil {
		t.Fatalf("append audit event: %v", err)
	}
	return event
}

func newTestService(t *testing.T, indexStore index.LeanIndexStore, auditStore audit.Store, revocationStore revocation.Store) *Service {
	t.Helper()
	service, err := NewService(indexStore, auditStore, revocationStore)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

type fakeIndexStore struct {
	record  index.IndexedRecord
	err     error
	gotHash [16]byte
}

func (s *fakeIndexStore) Put(_ context.Context, _ string, _ agentaddr.AgentAddr120) error {
	return nil
}

func (s *fakeIndexStore) Get(_ context.Context, agentHash [16]byte) (index.IndexedRecord, error) {
	s.gotHash = agentHash
	if s.err != nil {
		return index.IndexedRecord{}, s.err
	}
	return s.record, nil
}

func (s *fakeIndexStore) History(_ context.Context, _ [16]byte) ([]index.IndexedRecord, error) {
	return nil, nil
}

type fakeRevocationStore struct {
	record          revocation.Record
	err             error
	setErr          error
	setIssuer       string
	setCredentialID string
	setStatus       string
	setReason       string
}

func (s *fakeRevocationStore) SetStatus(_ context.Context, issuer string, credentialID string, status string, reason string) error {
	s.setIssuer = issuer
	s.setCredentialID = credentialID
	s.setStatus = status
	s.setReason = reason
	return s.setErr
}

func (s *fakeRevocationStore) GetStatus(_ context.Context, _ string, _ string) (revocation.Record, error) {
	if s.err != nil {
		return revocation.Record{}, s.err
	}
	return s.record, nil
}

func (s *fakeRevocationStore) IsRevoked(_ context.Context, _ string, _ string) (bool, error) {
	return false, nil
}

func TestGetRevocationStatusFound(t *testing.T) {
	updatedAt := time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	service := newTestService(t, &fakeIndexStore{}, audit.NewMemoryStore(), &fakeRevocationStore{
		record: revocation.Record{
			Issuer:       "issuer.example",
			CredentialID: "credential-1",
			Status:       revocation.StatusRevoked,
			Reason:       "compromised",
			UpdatedAt:    updatedAt,
		},
	})

	resp, err := service.GetRevocationStatus(context.Background(), "issuer.example", "credential-1")
	if err != nil {
		t.Fatalf("GetRevocationStatus returned error: %v", err)
	}
	if !resp.Found {
		t.Fatal("found = false, want true")
	}
	if resp.Status != revocation.StatusRevoked || resp.Reason != "compromised" {
		t.Fatalf("status/reason = %q/%q, want revoked/compromised", resp.Status, resp.Reason)
	}
	if resp.UpdatedAt == nil || !resp.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("updatedAt = %v, want %v", resp.UpdatedAt, updatedAt)
	}
}
