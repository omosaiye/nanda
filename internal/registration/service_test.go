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

	"github.com/solai/nanda/internal/agentaddr"
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
