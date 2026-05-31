package registration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/agentfacts"
	"github.com/solai/nanda/internal/audit"
	"github.com/solai/nanda/internal/facts"
	"github.com/solai/nanda/internal/index"
)

func TestServiceRegisterSuccess(t *testing.T) {
	_, privateKey := testKeyPair(t)
	factsStore := &fakeFactsStore{
		pointer: facts.FactsPointer{Scheme: "fs", Path: "ab/cd/agent.facts"},
	}
	indexStore := &fakeIndexStore{}
	service := newTestService(t, factsStore, indexStore, privateKey)

	req := RegisterRequest{
		AgentID:    "  Agent.Example ",
		TTLSeconds: 300,
		Flags:      1,
		Sequence:   42,
		Facts:      json.RawMessage(`{"endpoint":"https://agent.example"}`),
	}

	resp, err := service.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	wantAgentID := "agent.example"
	if resp.AgentID != wantAgentID {
		t.Fatalf("agent id = %q, want %q", resp.AgentID, wantAgentID)
	}
	if !bytes.Equal(factsStore.putFacts, req.Facts) {
		t.Fatalf("stored facts = %q, want %q", factsStore.putFacts, req.Facts)
	}
	if !indexStore.putCalled {
		t.Fatal("index store Put was not called")
	}
	if indexStore.agentID != wantAgentID {
		t.Fatalf("indexed agent id = %q, want %q", indexStore.agentID, wantAgentID)
	}

	recordBytes, err := base64.StdEncoding.DecodeString(resp.AgentAddrRecordBase64)
	if err != nil {
		t.Fatalf("decode response record base64: %v", err)
	}
	if len(recordBytes) != agentaddr.RecordSize {
		t.Fatalf("record length = %d, want %d", len(recordBytes), agentaddr.RecordSize)
	}

	record, err := agentaddr.Decode(recordBytes)
	if err != nil {
		t.Fatalf("decode record: %v", err)
	}
	if !bytes.Equal(indexStore.record.Encode(), recordBytes) {
		t.Fatal("indexed record differs from response record")
	}

	wantFactsHash := facts.PointerHash128(factsStore.pointer)
	if record.Payload().FactsPtrHash128 != wantFactsHash {
		t.Fatalf("record facts hash = %x, want %x", record.Payload().FactsPtrHash128, wantFactsHash)
	}
	if resp.FactsPtrHash128 != hex.EncodeToString(wantFactsHash[:]) {
		t.Fatalf("response facts hash = %q, want %x", resp.FactsPtrHash128, wantFactsHash)
	}

	wantCredentialSet := agentaddr.Hash128([]byte{})
	if record.Payload().CredentialSet128 != wantCredentialSet {
		t.Fatalf("record credential set = %x, want %x", record.Payload().CredentialSet128, wantCredentialSet)
	}
	if resp.CredentialSet128 != hex.EncodeToString(wantCredentialSet[:]) {
		t.Fatalf("response credential set = %q, want %x", resp.CredentialSet128, wantCredentialSet)
	}
}

func TestServiceRegisterCommitsCredentialSet128(t *testing.T) {
	_, privateKey := testKeyPair(t)
	factsStore := &fakeFactsStore{
		pointer: facts.FactsPointer{Scheme: "fs", Path: "ab/cd/agent.facts"},
	}
	indexStore := &fakeIndexStore{}
	service := newTestService(t, factsStore, indexStore, privateKey)
	credentials := []agentfacts.CapabilityCredential{
		testCapabilityCredential("credential-1", "signature-1"),
		testCapabilityCredential("credential-2", "signature-2"),
	}
	factsBytes := testAgentFactsBytes(t, credentials)

	resp, err := service.Register(context.Background(), RegisterRequest{
		AgentID:    "agent.example",
		TTLSeconds: 300,
		Sequence:   1,
		Facts:      factsBytes,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	wantCredentialSet, err := agentfacts.CredentialSetHash128(credentials)
	if err != nil {
		t.Fatalf("credential set hash: %v", err)
	}
	if indexStore.record.Payload().CredentialSet128 != wantCredentialSet {
		t.Fatalf("record credential set = %x, want %x", indexStore.record.Payload().CredentialSet128, wantCredentialSet)
	}
	if resp.CredentialSet128 != hex.EncodeToString(wantCredentialSet[:]) {
		t.Fatalf("response credential set = %q, want %x", resp.CredentialSet128, wantCredentialSet)
	}
}

func TestServiceRegisterStoresFactsPointerWhenConfigured(t *testing.T) {
	_, privateKey := testKeyPair(t)
	pointerStore := &fakePointerStore{}
	factsStore := &fakeFactsStore{
		pointer: facts.FactsPointer{Scheme: "fs", Path: "ab/cd/agent.facts"},
	}
	service, err := NewService(
		factsStore,
		&fakeIndexStore{},
		privateKey,
		WithPointerStore(pointerStore),
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	_, err = service.Register(context.Background(), RegisterRequest{
		AgentID:    "agent.example",
		TTLSeconds: 300,
		Sequence:   1,
		Facts:      json.RawMessage(`{"endpoint":"https://agent.example"}`),
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !pointerStore.putCalled {
		t.Fatal("pointer store PutFactsPointer was not called")
	}
	if pointerStore.pointer != factsStore.pointer {
		t.Fatalf("stored pointer = %+v, want %+v", pointerStore.pointer, factsStore.pointer)
	}
}

func TestServiceRegisterWritesAuditEvent(t *testing.T) {
	_, privateKey := testKeyPair(t)
	auditStore := audit.NewMemoryStore()
	service, err := NewService(
		&fakeFactsStore{pointer: facts.FactsPointer{Scheme: "fs", Path: "ab/cd/agent.facts"}},
		&fakeIndexStore{},
		privateKey,
		WithAuditStore(auditStore),
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	_, err = service.Register(context.Background(), RegisterRequest{
		AgentID:    "Agent.Example",
		TTLSeconds: 300,
		Sequence:   1,
		Facts:      json.RawMessage(`{"endpoint":"https://agent.example"}`),
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	events, err := auditStore.List(context.Background())
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	event := events[0]
	if event.EventType != audit.EventAgentRegistered {
		t.Fatalf("event type = %q, want %q", event.EventType, audit.EventAgentRegistered)
	}
	if event.Decision != audit.DecisionAllowed {
		t.Fatalf("decision = %q, want %q", event.Decision, audit.DecisionAllowed)
	}
	if event.AgentID != "agent.example" {
		t.Fatalf("agent id = %q, want agent.example", event.AgentID)
	}
	if event.AgentHash == "" || event.EventHash == "" {
		t.Fatalf("missing audit hashes: agentHash=%q eventHash=%q", event.AgentHash, event.EventHash)
	}
	if err := auditStore.VerifyHashChain(context.Background()); err != nil {
		t.Fatalf("verify audit hash chain: %v", err)
	}
}

func TestServiceRegisterMissingAgentIDValidationError(t *testing.T) {
	service := newTestService(t, &fakeFactsStore{}, &fakeIndexStore{}, testPrivateKey(t))

	_, err := service.Register(context.Background(), RegisterRequest{
		TTLSeconds: 300,
		Facts:      json.RawMessage(`{}`),
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("register error = %v, want validation error", err)
	}
}

func TestServiceRegisterZeroTTLValidationError(t *testing.T) {
	service := newTestService(t, &fakeFactsStore{}, &fakeIndexStore{}, testPrivateKey(t))

	_, err := service.Register(context.Background(), RegisterRequest{
		AgentID: "agent.example",
		Facts:   json.RawMessage(`{}`),
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("register error = %v, want validation error", err)
	}
}

func TestServiceRegisterInvalidJSONFactsValidationError(t *testing.T) {
	service := newTestService(t, &fakeFactsStore{}, &fakeIndexStore{}, testPrivateKey(t))

	_, err := service.Register(context.Background(), RegisterRequest{
		AgentID:    "agent.example",
		TTLSeconds: 300,
		Facts:      json.RawMessage(`{"broken"`),
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("register error = %v, want validation error", err)
	}
}

type fakeFactsStore struct {
	pointer  facts.FactsPointer
	putFacts []byte
}

func (s *fakeFactsStore) Put(_ context.Context, factsBytes []byte) (facts.FactsPointer, error) {
	s.putFacts = append([]byte(nil), factsBytes...)
	return s.pointer, nil
}

func (s *fakeFactsStore) Get(_ context.Context, _ facts.FactsPointer) ([]byte, error) {
	return nil, facts.ErrNotFound
}

type fakeIndexStore struct {
	putCalled bool
	agentID   string
	record    agentaddr.AgentAddr120
}

func (s *fakeIndexStore) Put(_ context.Context, agentID string, record agentaddr.AgentAddr120) error {
	s.putCalled = true
	s.agentID = agentID
	s.record = record
	return nil
}

func (s *fakeIndexStore) Get(_ context.Context, _ [16]byte) (index.IndexedRecord, error) {
	return index.IndexedRecord{}, index.ErrNotFound
}

func (s *fakeIndexStore) History(_ context.Context, _ [16]byte) ([]index.IndexedRecord, error) {
	return nil, nil
}

type fakePointerStore struct {
	putCalled bool
	pointer   facts.FactsPointer
}

func (s *fakePointerStore) PutFactsPointer(_ context.Context, pointer facts.FactsPointer) error {
	s.putCalled = true
	s.pointer = pointer
	return nil
}

func (s *fakePointerStore) ResolveFactsPointer(_ context.Context, _ [16]byte) (facts.FactsPointer, error) {
	return facts.FactsPointer{}, facts.ErrNotFound
}

func newTestService(t *testing.T, factsStore facts.FactsStore, indexStore index.LeanIndexStore, privateKey ed25519.PrivateKey) *Service {
	t.Helper()

	service, err := NewService(factsStore, indexStore, privateKey)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return publicKey, privateKey
}

func testPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, privateKey := testKeyPair(t)
	return privateKey
}

func testAgentFactsBytes(t *testing.T, credentials []agentfacts.CapabilityCredential) json.RawMessage {
	t.Helper()

	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	factsBytes, err := json.Marshal(agentfacts.AgentFacts{
		SchemaVersion: agentfacts.SchemaVersionV0,
		ID:            "agent.example",
		Controller:    "did:example:controller",
		ValidFrom:     now.Add(-time.Minute),
		ValidUntil:    now.Add(time.Hour),
		Capabilities:  []string{"chat"},
		Credentials:   credentials,
		Endpoints: []agentfacts.Endpoint{
			{
				ID:         "primary",
				Type:       agentfacts.EndpointTypeStatic,
				URL:        "https://agent.example/endpoint",
				Protocol:   "https",
				TTLSeconds: 60,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	return factsBytes
}

func testCapabilityCredential(id string, signature string) agentfacts.CapabilityCredential {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	return agentfacts.CapabilityCredential{
		ID:           id,
		Type:         agentfacts.AgentCapabilityCredential,
		Issuer:       "did:example:issuer",
		Subject:      "agent.example",
		Capabilities: []string{"chat", "status"},
		ValidFrom:    now.Add(-time.Minute),
		ValidUntil:   now.Add(time.Hour),
		Signature:    signature,
	}
}
