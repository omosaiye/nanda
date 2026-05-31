package resolver

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/agentfacts"
	"github.com/solai/nanda/internal/facts"
	"github.com/solai/nanda/internal/index"
)

func TestServiceResolveSuccess(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecord(t, "agent.example", facts.PointerHash128(pointer), privateKey)
	service := newTestService(t, publicKey, record, pointer, testFactsBytes(t, []agentfacts.Endpoint{
		testEndpoint("static", agentfacts.EndpointTypeStatic),
	}))

	resp, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID:            " Agent.Example ",
		RequiredCapability: "chat",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if resp.AgentID != "agent.example" {
		t.Fatalf("agent id = %q, want agent.example", resp.AgentID)
	}
	if resp.Endpoint.ID != "static" {
		t.Fatalf("endpoint id = %q, want static", resp.Endpoint.ID)
	}
	if resp.TrustDecision != TrustDecisionUnverifiedV0 {
		t.Fatalf("trust decision = %q, want %q", resp.TrustDecision, TrustDecisionUnverifiedV0)
	}
	if !resp.ProofBundle.AgentAddrSignatureVerified {
		t.Fatal("agent address signature proof was not verified")
	}
	if !resp.ProofBundle.AgentFactsPointerHashVerified {
		t.Fatal("agent facts pointer hash proof was not verified")
	}
	if !resp.ProofBundle.AgentFactsSchemaVerified {
		t.Fatal("agent facts schema proof was not verified")
	}
	if resp.ProofBundle.CredentialStatus != CredentialStatusNotImplemented {
		t.Fatalf("credential status = %q, want %q", resp.ProofBundle.CredentialStatus, CredentialStatusNotImplemented)
	}
}

func TestServiceResolveMissingIndexRecordReturnsNotFound(t *testing.T) {
	publicKey, _ := testKeyPair(t)
	service, err := NewService(&fakeIndexStore{getErr: index.ErrNotFound}, &fakeFactsStore{}, &fakePointerResolver{}, publicKey)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	_, err = service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("resolve error = %v, want not found", err)
	}
}

func TestServiceResolveMissingAgentFactsReturnsNotFound(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecord(t, "agent.example", facts.PointerHash128(pointer), privateKey)
	service, err := NewService(
		&fakeIndexStore{record: record},
		&fakeFactsStore{pointer: pointer, getErr: facts.ErrNotFound},
		&fakePointerResolver{pointer: pointer},
		publicKey,
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	_, err = service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("resolve error = %v, want not found", err)
	}
}

func TestServiceResolveBadSignatureFails(t *testing.T) {
	publicKey, _ := testKeyPair(t)
	_, signingKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecord(t, "agent.example", facts.PointerHash128(pointer), signingKey)
	service := newTestService(t, publicKey, record, pointer, testFactsBytes(t, []agentfacts.Endpoint{
		testEndpoint("static", agentfacts.EndpointTypeStatic),
	}))

	_, err := service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("resolve error = %v, want verification error", err)
	}
}

func TestServiceResolveFactsPointerHashMismatchFails(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	recordPointer := facts.FactsPointer{Scheme: "mem", Path: "record-pointer"}
	resolvedPointer := facts.FactsPointer{Scheme: "mem", Path: "different-pointer"}
	record := testRecord(t, "agent.example", facts.PointerHash128(recordPointer), privateKey)
	service := newTestService(t, publicKey, record, resolvedPointer, testFactsBytes(t, []agentfacts.Endpoint{
		testEndpoint("static", agentfacts.EndpointTypeStatic),
	}))

	_, err := service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("resolve error = %v, want verification error", err)
	}
}

func TestServiceResolveInvalidAgentFactsSchemaFails(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecord(t, "agent.example", facts.PointerHash128(pointer), privateKey)
	service := newTestService(t, publicKey, record, pointer, []byte(`{"schemaVersion":"nanda.agentfacts.v0","id":"agent.example","controller":"did:example:controller","validFrom":"2026-05-31T11:00:00Z","validUntil":"2026-06-01T12:00:00Z","capabilities":["chat"],"endpoints":[{"id":"bad","type":"static","url":"://bad","protocol":"https","ttlSeconds":60}]}`))

	_, err := service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if !errors.Is(err, agentfacts.ErrValidation) {
		t.Fatalf("resolve error = %v, want agent facts validation error", err)
	}
}

func TestServiceResolveMissingRequiredCapabilityFails(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecord(t, "agent.example", facts.PointerHash128(pointer), privateKey)
	service := newTestService(t, publicKey, record, pointer, testFactsBytes(t, []agentfacts.Endpoint{
		testEndpoint("static", agentfacts.EndpointTypeStatic),
	}))

	_, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID:            "agent.example",
		RequiredCapability: "payments",
	})
	if !errors.Is(err, agentfacts.ErrValidation) {
		t.Fatalf("resolve error = %v, want agent facts validation error", err)
	}
}

func TestServiceResolveEndpointSelectionPriority(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecord(t, "agent.example", facts.PointerHash128(pointer), privateKey)
	service := newTestService(t, publicKey, record, pointer, testFactsBytes(t, []agentfacts.Endpoint{
		testEndpoint("static", agentfacts.EndpointTypeStatic),
		testEndpoint("rotating", agentfacts.EndpointTypeRotating),
		testEndpoint("adaptive", agentfacts.EndpointTypeAdaptiveResolver),
	}))

	resp, err := service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resp.Endpoint.ID != "adaptive" {
		t.Fatalf("endpoint id = %q, want adaptive", resp.Endpoint.ID)
	}

	service = newTestService(t, publicKey, record, pointer, testFactsBytes(t, []agentfacts.Endpoint{
		testEndpoint("static", agentfacts.EndpointTypeStatic),
		testEndpoint("rotating", agentfacts.EndpointTypeRotating),
	}))
	resp, err = service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if err != nil {
		t.Fatalf("resolve rotating: %v", err)
	}
	if resp.Endpoint.ID != "rotating" {
		t.Fatalf("endpoint id = %q, want rotating", resp.Endpoint.ID)
	}
}

type fakeIndexStore struct {
	record agentaddr.AgentAddr120
	getErr error
}

func (s *fakeIndexStore) Put(_ context.Context, _ string, _ agentaddr.AgentAddr120) error {
	return nil
}

func (s *fakeIndexStore) Get(_ context.Context, agentHash [16]byte) (index.IndexedRecord, error) {
	if s.getErr != nil {
		return index.IndexedRecord{}, s.getErr
	}
	return index.IndexedRecord{AgentHash: agentHash, AgentID: "agent.example", Record: s.record}, nil
}

func (s *fakeIndexStore) History(_ context.Context, _ [16]byte) ([]index.IndexedRecord, error) {
	return nil, nil
}

type fakeFactsStore struct {
	pointer facts.FactsPointer
	data    []byte
	getErr  error
}

func (s *fakeFactsStore) Put(_ context.Context, _ []byte) (facts.FactsPointer, error) {
	return facts.FactsPointer{}, nil
}

func (s *fakeFactsStore) Get(_ context.Context, pointer facts.FactsPointer) ([]byte, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if pointer != s.pointer {
		return nil, facts.ErrNotFound
	}
	return append([]byte(nil), s.data...), nil
}

type fakePointerResolver struct {
	pointer facts.FactsPointer
	err     error
}

func (r *fakePointerResolver) ResolveFactsPointer(_ context.Context, _ [16]byte) (facts.FactsPointer, error) {
	if r.err != nil {
		return facts.FactsPointer{}, r.err
	}
	return r.pointer, nil
}

func newTestService(t *testing.T, publicKey ed25519.PublicKey, record agentaddr.AgentAddr120, pointer facts.FactsPointer, factsBytes []byte) *Service {
	t.Helper()

	service, err := NewService(
		&fakeIndexStore{record: record},
		&fakeFactsStore{pointer: pointer, data: factsBytes},
		&fakePointerResolver{pointer: pointer},
		publicKey,
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	service.now = func() time.Time { return time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC) }
	return service
}

func testRecord(t *testing.T, agentID string, factsPtrHash [16]byte, privateKey ed25519.PrivateKey) agentaddr.AgentAddr120 {
	t.Helper()

	payload, err := agentaddr.New(agentID, 300, 0, 1, factsPtrHash, agentaddr.Hash128(nil))
	if err != nil {
		t.Fatalf("new payload: %v", err)
	}
	record, err := agentaddr.Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	return record
}

func testFactsBytes(t *testing.T, endpoints []agentfacts.Endpoint) []byte {
	t.Helper()

	validFrom := time.Date(2026, 5, 31, 11, 0, 0, 0, time.UTC)
	validUntil := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	factsBytes, err := json.Marshal(agentfacts.AgentFacts{
		SchemaVersion: agentfacts.SchemaVersionV0,
		ID:            "agent.example",
		Controller:    "did:example:controller",
		ValidFrom:     validFrom,
		ValidUntil:    validUntil,
		Capabilities:  []string{"chat"},
		Endpoints:     endpoints,
	})
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	return factsBytes
}

func testEndpoint(id string, endpointType string) agentfacts.Endpoint {
	return agentfacts.Endpoint{
		ID:         id,
		Type:       endpointType,
		URL:        "https://" + id + ".agent.example",
		Protocol:   "https",
		TTLSeconds: 60,
	}
}

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return publicKey, privateKey
}
