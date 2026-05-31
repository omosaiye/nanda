package resolver

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/agentfacts"
	"github.com/solai/nanda/internal/audit"
	"github.com/solai/nanda/internal/facts"
	"github.com/solai/nanda/internal/index"
	"github.com/solai/nanda/internal/revocation"
	"github.com/solai/nanda/internal/trust"
)

func TestServiceResolveSuccess(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecord(t, "agent.example", facts.PointerHash128(pointer), privateKey)
	service := newTestService(t, publicKey, record, pointer, testFactsBytes(t, []agentfacts.Endpoint{
		testEndpoint("static", agentfacts.EndpointTypeStatic),
	}))

	resp, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID: " Agent.Example ",
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
	if !resp.ProofBundle.CredentialSetVerified {
		t.Fatal("credential set proof was not verified")
	}
	if resp.ProofBundle.CredentialStatus != CredentialStatusNotImplemented {
		t.Fatalf("credential status = %q, want %q", resp.ProofBundle.CredentialStatus, CredentialStatusNotImplemented)
	}
	if resp.ProofBundle.CapabilityCredentialVerified {
		t.Fatal("capability credential proof was verified without a required capability")
	}
}

func TestServiceResolveSuccessWritesAuditEvent(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecord(t, "agent.example", facts.PointerHash128(pointer), privateKey)
	auditStore := audit.NewMemoryStore()
	service := newTestServiceWithOptions(t, publicKey, record, pointer, testFactsBytes(t, []agentfacts.Endpoint{
		testEndpoint("static", agentfacts.EndpointTypeStatic),
	}), WithAuditStore(auditStore))

	if _, err := service.Resolve(context.Background(), ResolveRequest{AgentID: "Agent.Example"}); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	events := requireAuditEvents(t, auditStore, 1)
	event := events[0]
	if event.EventType != audit.EventResolveAllowed {
		t.Fatalf("event type = %q, want %q", event.EventType, audit.EventResolveAllowed)
	}
	if event.Decision != audit.DecisionAllowed {
		t.Fatalf("decision = %q, want %q", event.Decision, audit.DecisionAllowed)
	}
	if event.AgentID != "agent.example" {
		t.Fatalf("agent id = %q, want agent.example", event.AgentID)
	}
}

func TestServiceResolveRequiredCapabilityWithValidCredential(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	issuerPublicKey, issuerPrivateKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	credential := testCapabilityCredential()
	signCredential(t, &credential, issuerPrivateKey)
	credentialSet128, err := agentfacts.CredentialSetHash128([]agentfacts.CapabilityCredential{credential})
	if err != nil {
		t.Fatalf("credential set hash: %v", err)
	}
	record := testRecordWithCredentialSet(t, "agent.example", facts.PointerHash128(pointer), credentialSet128, privateKey)
	verifier := testTrustVerifier(t, issuerPublicKey)
	service := newTestServiceWithOptions(t, publicKey, record, pointer, testFactsBytesWithCredentials(t, []agentfacts.CapabilityCredential{credential}), WithTrustVerifier(verifier))

	resp, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID:            " Agent.Example ",
		RequiredCapability: "chat",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if resp.TrustDecision != TrustDecisionVerifiedV0 {
		t.Fatalf("trust decision = %q, want %q", resp.TrustDecision, TrustDecisionVerifiedV0)
	}
	if !resp.ProofBundle.CapabilityCredentialVerified {
		t.Fatal("capability credential proof was not verified")
	}
	if resp.ProofBundle.CredentialStatus != CredentialStatusNotImplemented {
		t.Fatalf("credential status = %q, want %q", resp.ProofBundle.CredentialStatus, CredentialStatusNotImplemented)
	}
}

func TestServiceResolveVerifiesCredentialSet128(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	credential := testCapabilityCredential()
	credential.Signature = "signature-1"
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	credentialSet128, err := agentfacts.CredentialSetHash128([]agentfacts.CapabilityCredential{credential})
	if err != nil {
		t.Fatalf("credential set hash: %v", err)
	}
	record := testRecordWithCredentialSet(t, "agent.example", facts.PointerHash128(pointer), credentialSet128, privateKey)
	service := newTestService(t, publicKey, record, pointer, testFactsBytesWithCredentials(t, []agentfacts.CapabilityCredential{credential}))

	resp, err := service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !resp.ProofBundle.CredentialSetVerified {
		t.Fatal("credential set proof was not verified")
	}
}

func TestServiceResolveRejectsCredentialSetMismatch(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	credential := testCapabilityCredential()
	credential.Signature = "signature-1"
	committedCredential := credential
	committedHash, err := agentfacts.CredentialSetHash128([]agentfacts.CapabilityCredential{committedCredential})
	if err != nil {
		t.Fatalf("credential set hash: %v", err)
	}
	tamperedCredential := credential
	tamperedCredential.Signature = "tampered-signature"

	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecordWithCredentialSet(t, "agent.example", facts.PointerHash128(pointer), committedHash, privateKey)
	service := newTestService(t, publicKey, record, pointer, testFactsBytesWithCredentials(t, []agentfacts.CapabilityCredential{tamperedCredential}))

	_, err = service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("resolve error = %v, want verification error", err)
	}
}

func TestServiceResolveRequiredCapabilityWithUntrustedIssuerFails(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	issuerPublicKey, issuerPrivateKey := testKeyPair(t)
	credential := testCapabilityCredential()
	credential.Issuer = "did:example:untrusted"
	signCredential(t, &credential, issuerPrivateKey)
	service := newCredentialTestService(t, publicKey, privateKey, []agentfacts.CapabilityCredential{credential}, issuerPublicKey)

	_, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID:            "agent.example",
		RequiredCapability: "chat",
	})
	if !errors.Is(err, ErrTrustDenied) {
		t.Fatalf("resolve error = %v, want trust denied", err)
	}
}

func TestServiceResolveTrustDenialWritesAuditEvent(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	issuerPublicKey, issuerPrivateKey := testKeyPair(t)
	credential := testCapabilityCredential()
	credential.Issuer = "did:example:untrusted"
	signCredential(t, &credential, issuerPrivateKey)
	auditStore := audit.NewMemoryStore()
	service := newCredentialTestServiceWithOptions(t, publicKey, privateKey, []agentfacts.CapabilityCredential{credential}, issuerPublicKey, WithAuditStore(auditStore))

	_, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID:            "agent.example",
		RequiredCapability: "chat",
	})
	if !errors.Is(err, ErrTrustDenied) {
		t.Fatalf("resolve error = %v, want trust denied", err)
	}

	events := requireAuditEvents(t, auditStore, 1)
	event := events[0]
	if event.EventType != audit.EventTrustDenied {
		t.Fatalf("event type = %q, want %q", event.EventType, audit.EventTrustDenied)
	}
	if event.Decision != audit.DecisionDenied {
		t.Fatalf("decision = %q, want %q", event.Decision, audit.DecisionDenied)
	}
	if event.Reason == "" {
		t.Fatal("trust denial audit event reason is empty")
	}
}

func TestServiceResolveRequiredCapabilityWithRevokedCredentialFailsAndWritesAuditEvent(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	issuerPublicKey, issuerPrivateKey := testKeyPair(t)
	credential := testCapabilityCredential()
	signCredential(t, &credential, issuerPrivateKey)
	revocationStore := revocation.NewMemoryStore()
	if err := revocationStore.SetStatus(context.Background(), credential.Issuer, credential.ID, revocation.StatusRevoked, "compromised"); err != nil {
		t.Fatalf("set revoked: %v", err)
	}
	verifier, err := trust.NewVerifier(
		trust.IssuerAllowlist{"did:example:issuer": issuerPublicKey},
		trust.WithRevocationChecker(revocationStore),
	)
	if err != nil {
		t.Fatalf("new trust verifier: %v", err)
	}

	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	credentialSet128, err := agentfacts.CredentialSetHash128([]agentfacts.CapabilityCredential{credential})
	if err != nil {
		t.Fatalf("credential set hash: %v", err)
	}
	record := testRecordWithCredentialSet(t, "agent.example", facts.PointerHash128(pointer), credentialSet128, privateKey)
	auditStore := audit.NewMemoryStore()
	service := newTestServiceWithOptions(
		t,
		publicKey,
		record,
		pointer,
		testFactsBytesWithCredentials(t, []agentfacts.CapabilityCredential{credential}),
		WithTrustVerifier(verifier),
		WithAuditStore(auditStore),
	)

	_, err = service.Resolve(context.Background(), ResolveRequest{
		AgentID:            "agent.example",
		RequiredCapability: "chat",
	})
	if !errors.Is(err, ErrTrustDenied) {
		t.Fatalf("resolve error = %v, want trust denied", err)
	}
	if !errors.Is(err, trust.ErrCredentialRevoked) {
		t.Fatalf("resolve error = %v, want credential revoked", err)
	}

	events := requireAuditEvents(t, auditStore, 1)
	event := events[0]
	if event.EventType != audit.EventTrustDenied {
		t.Fatalf("event type = %q, want %q", event.EventType, audit.EventTrustDenied)
	}
	if event.Decision != audit.DecisionDenied {
		t.Fatalf("decision = %q, want %q", event.Decision, audit.DecisionDenied)
	}
	if event.Reason == "" {
		t.Fatal("trust denial audit event reason is empty")
	}
}

func TestServiceResolveRequiredCapabilityWithBadCredentialSignatureFails(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	issuerPublicKey, _ := testKeyPair(t)
	_, wrongIssuerPrivateKey := testKeyPair(t)
	credential := testCapabilityCredential()
	signCredential(t, &credential, wrongIssuerPrivateKey)
	service := newCredentialTestService(t, publicKey, privateKey, []agentfacts.CapabilityCredential{credential}, issuerPublicKey)

	_, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID:            "agent.example",
		RequiredCapability: "chat",
	})
	if !errors.Is(err, ErrTrustDenied) {
		t.Fatalf("resolve error = %v, want trust denied", err)
	}
}

func TestServiceResolveRequiredCapabilityWithSubjectMismatchFails(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	issuerPublicKey, issuerPrivateKey := testKeyPair(t)
	credential := testCapabilityCredential()
	credential.Subject = "other.example"
	signCredential(t, &credential, issuerPrivateKey)
	service := newCredentialTestService(t, publicKey, privateKey, []agentfacts.CapabilityCredential{credential}, issuerPublicKey)

	_, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID:            "agent.example",
		RequiredCapability: "chat",
	})
	if !errors.Is(err, ErrTrustDenied) {
		t.Fatalf("resolve error = %v, want trust denied", err)
	}
}

func TestServiceResolveRequiredCapabilityWithExpiredCredentialFails(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	issuerPublicKey, issuerPrivateKey := testKeyPair(t)
	credential := testCapabilityCredential()
	credential.ValidUntil = time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	signCredential(t, &credential, issuerPrivateKey)
	service := newCredentialTestService(t, publicKey, privateKey, []agentfacts.CapabilityCredential{credential}, issuerPublicKey)

	_, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID:            "agent.example",
		RequiredCapability: "chat",
	})
	if !errors.Is(err, ErrTrustDenied) {
		t.Fatalf("resolve error = %v, want trust denied", err)
	}
}

func TestServiceResolveRequiredCapabilityMissingCredentialCapabilityFails(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	issuerPublicKey, issuerPrivateKey := testKeyPair(t)
	credential := testCapabilityCredential()
	credential.Capabilities = []string{"status"}
	signCredential(t, &credential, issuerPrivateKey)
	service := newCredentialTestService(t, publicKey, privateKey, []agentfacts.CapabilityCredential{credential}, issuerPublicKey)

	_, err := service.Resolve(context.Background(), ResolveRequest{
		AgentID:            "agent.example",
		RequiredCapability: "chat",
	})
	if !errors.Is(err, ErrTrustDenied) {
		t.Fatalf("resolve error = %v, want trust denied", err)
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

func TestServiceResolveVerificationFailureWritesAuditEvent(t *testing.T) {
	publicKey, _ := testKeyPair(t)
	_, signingKey := testKeyPair(t)
	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	record := testRecord(t, "agent.example", facts.PointerHash128(pointer), signingKey)
	auditStore := audit.NewMemoryStore()
	service := newTestServiceWithOptions(t, publicKey, record, pointer, testFactsBytes(t, []agentfacts.Endpoint{
		testEndpoint("static", agentfacts.EndpointTypeStatic),
	}), WithAuditStore(auditStore))

	_, err := service.Resolve(context.Background(), ResolveRequest{AgentID: "agent.example"})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("resolve error = %v, want verification error", err)
	}

	events := requireAuditEvents(t, auditStore, 1)
	event := events[0]
	if event.EventType != audit.EventResolveDenied {
		t.Fatalf("event type = %q, want %q", event.EventType, audit.EventResolveDenied)
	}
	if event.Decision != audit.DecisionDenied {
		t.Fatalf("decision = %q, want %q", event.Decision, audit.DecisionDenied)
	}
	if event.Reason == "" {
		t.Fatal("verification failure audit event reason is empty")
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

	return newTestServiceWithOptions(t, publicKey, record, pointer, factsBytes)
}

func newTestServiceWithOptions(t *testing.T, publicKey ed25519.PublicKey, record agentaddr.AgentAddr120, pointer facts.FactsPointer, factsBytes []byte, opts ...Option) *Service {
	t.Helper()

	service, err := NewService(
		&fakeIndexStore{record: record},
		&fakeFactsStore{pointer: pointer, data: factsBytes},
		&fakePointerResolver{pointer: pointer},
		publicKey,
		opts...,
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	service.now = func() time.Time { return time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC) }
	return service
}

func newCredentialTestService(t *testing.T, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, credentials []agentfacts.CapabilityCredential, issuerPublicKey ed25519.PublicKey) *Service {
	t.Helper()

	return newCredentialTestServiceWithOptions(t, publicKey, privateKey, credentials, issuerPublicKey)
}

func newCredentialTestServiceWithOptions(t *testing.T, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, credentials []agentfacts.CapabilityCredential, issuerPublicKey ed25519.PublicKey, opts ...Option) *Service {
	t.Helper()

	pointer := facts.FactsPointer{Scheme: "mem", Path: "agent.example"}
	credentialSet128, err := agentfacts.CredentialSetHash128(credentials)
	if err != nil {
		t.Fatalf("credential set hash: %v", err)
	}
	record := testRecordWithCredentialSet(t, "agent.example", facts.PointerHash128(pointer), credentialSet128, privateKey)
	verifier := testTrustVerifier(t, issuerPublicKey)
	opts = append(opts, WithTrustVerifier(verifier))
	return newTestServiceWithOptions(t, publicKey, record, pointer, testFactsBytesWithCredentials(t, credentials), opts...)
}

func testRecord(t *testing.T, agentID string, factsPtrHash [16]byte, privateKey ed25519.PrivateKey) agentaddr.AgentAddr120 {
	t.Helper()

	return testRecordWithCredentialSet(t, agentID, factsPtrHash, agentaddr.Hash128(nil), privateKey)
}

func testRecordWithCredentialSet(t *testing.T, agentID string, factsPtrHash [16]byte, credentialSet128 [16]byte, privateKey ed25519.PrivateKey) agentaddr.AgentAddr120 {
	t.Helper()

	payload, err := agentaddr.New(agentID, 300, 0, 1, factsPtrHash, credentialSet128)
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

func testFactsBytesWithCredentials(t *testing.T, credentials []agentfacts.CapabilityCredential) []byte {
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
		Credentials:   credentials,
		Endpoints: []agentfacts.Endpoint{
			testEndpoint("static", agentfacts.EndpointTypeStatic),
		},
	})
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	return factsBytes
}

func testCapabilityCredential() agentfacts.CapabilityCredential {
	return agentfacts.CapabilityCredential{
		ID:           "credential-1",
		Type:         agentfacts.AgentCapabilityCredential,
		Issuer:       "did:example:issuer",
		Subject:      "agent.example",
		Capabilities: []string{"chat", "status"},
		ValidFrom:    time.Date(2026, 5, 31, 11, 0, 0, 0, time.UTC),
		ValidUntil:   time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
	}
}

func signCredential(t *testing.T, credential *agentfacts.CapabilityCredential, privateKey ed25519.PrivateKey) {
	t.Helper()

	payload, err := json.Marshal(credentialSigningPayload{
		ID:           credential.ID,
		Type:         credential.Type,
		Issuer:       credential.Issuer,
		Subject:      credential.Subject,
		Capabilities: credential.Capabilities,
		ValidFrom:    credential.ValidFrom,
		ValidUntil:   credential.ValidUntil,
	})
	if err != nil {
		t.Fatalf("marshal credential signing payload: %v", err)
	}
	credential.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
}

type credentialSigningPayload struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	Capabilities []string  `json:"capabilities"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidUntil   time.Time `json:"validUntil"`
}

func testTrustVerifier(t *testing.T, issuerPublicKey ed25519.PublicKey) *trust.Verifier {
	t.Helper()

	verifier, err := trust.NewVerifier(trust.IssuerAllowlist{"did:example:issuer": issuerPublicKey})
	if err != nil {
		t.Fatalf("new trust verifier: %v", err)
	}
	return verifier
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

func requireAuditEvents(t *testing.T, store *audit.MemoryStore, want int) []audit.Event {
	t.Helper()

	events, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != want {
		t.Fatalf("audit event count = %d, want %d", len(events), want)
	}
	if err := store.VerifyHashChain(context.Background()); err != nil {
		t.Fatalf("verify audit hash chain: %v", err)
	}
	return events
}
