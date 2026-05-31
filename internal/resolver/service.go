package resolver

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/agentfacts"
	"github.com/solai/nanda/internal/audit"
	"github.com/solai/nanda/internal/facts"
	"github.com/solai/nanda/internal/index"
)

const (
	TrustDecisionUnverifiedV0      = "unverified-v0"
	TrustDecisionVerifiedV0        = "verified-v0"
	CredentialStatusNotImplemented = "not-implemented-v0"
)

var (
	ErrValidation             = errors.New("resolve validation failed")
	ErrNotFound               = errors.New("resolve record not found")
	ErrVerification           = errors.New("resolve verification failed")
	ErrMissingIndexStore      = errors.New("resolver service requires an index store")
	ErrMissingFactsStore      = errors.New("resolver service requires a facts store")
	ErrMissingPointerResolver = errors.New("resolver service requires a facts pointer resolver")
	ErrNoEndpoint             = errors.New("no endpoint available")
	ErrTrustDenied            = errors.New("resolve trust denied")
)

type ValidationError struct {
	Field string
	Err   error
}

func (e ValidationError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%v: %v", ErrValidation, e.Err)
	}
	return fmt.Sprintf("%v: %s: %v", ErrValidation, e.Field, e.Err)
}

func (e ValidationError) Unwrap() error {
	return e.Err
}

func (e ValidationError) Is(target error) bool {
	return target == ErrValidation
}

type VerificationError struct {
	Step string
	Err  error
}

func (e VerificationError) Error() string {
	if e.Step == "" {
		return fmt.Sprintf("%v: %v", ErrVerification, e.Err)
	}
	return fmt.Sprintf("%v: %s: %v", ErrVerification, e.Step, e.Err)
}

func (e VerificationError) Unwrap() error {
	return e.Err
}

func (e VerificationError) Is(target error) bool {
	return target == ErrVerification
}

type FactsPointerResolver interface {
	ResolveFactsPointer(ctx context.Context, factsPtrHash128 [16]byte) (facts.FactsPointer, error)
}

type TrustVerifier interface {
	VerifyCapability(credentials []agentfacts.CapabilityCredential, requestedAgentID string, requiredCapability string, now time.Time) error
}

type Option func(*Service)

type Service struct {
	indexStore      index.LeanIndexStore
	factsStore      facts.FactsStore
	pointerResolver FactsPointerResolver
	publicKey       ed25519.PublicKey
	trustVerifier   TrustVerifier
	auditStore      audit.Store
	now             func() time.Time
}

type ResolveRequest struct {
	AgentID            string `json:"agentId"`
	RequiredCapability string `json:"requiredCapability,omitempty"`
}

type ResolveResponse struct {
	AgentID       string              `json:"agentId"`
	Endpoint      agentfacts.Endpoint `json:"endpoint"`
	TrustDecision string              `json:"trustDecision"`
	ProofBundle   ProofBundle         `json:"proofBundle"`
}

type ProofBundle struct {
	AgentAddrSignatureVerified    bool   `json:"agentAddrSignatureVerified"`
	AgentFactsPointerHashVerified bool   `json:"agentFactsPointerHashVerified"`
	AgentFactsSchemaVerified      bool   `json:"agentFactsSchemaVerified"`
	CredentialStatus              string `json:"credentialStatus"`
	CapabilityCredentialVerified  bool   `json:"capabilityCredentialVerified"`
}

func WithTrustVerifier(verifier TrustVerifier) Option {
	return func(s *Service) {
		s.trustVerifier = verifier
	}
}

func WithAuditStore(store audit.Store) Option {
	return func(s *Service) {
		s.auditStore = store
	}
}

func NewService(indexStore index.LeanIndexStore, factsStore facts.FactsStore, pointerResolver FactsPointerResolver, publicKey ed25519.PublicKey, opts ...Option) (*Service, error) {
	if indexStore == nil {
		return nil, ErrMissingIndexStore
	}
	if factsStore == nil {
		return nil, ErrMissingFactsStore
	}
	if pointerResolver == nil {
		return nil, ErrMissingPointerResolver
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, agentaddr.ErrInvalidPublicKey
	}

	service := &Service{
		indexStore:      indexStore,
		factsStore:      factsStore,
		pointerResolver: pointerResolver,
		publicKey:       publicKey,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(service)
	}

	return service, nil
}

func (s *Service) Resolve(ctx context.Context, req ResolveRequest) (ResolveResponse, error) {
	agentID, err := agentaddr.NormalizeAgentID(req.AgentID)
	if err != nil {
		resolveErr := ValidationError{Field: "agentId", Err: err}
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, "", "", audit.EventResolveDenied, resolveErr)
	}

	agentHash, err := agentaddr.AgentIDHash(agentID)
	if err != nil {
		resolveErr := ValidationError{Field: "agentId", Err: err}
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, "", audit.EventResolveDenied, resolveErr)
	}
	agentHashHex := fmt.Sprintf("%x", agentHash[:])

	indexedRecord, err := s.indexStore.Get(ctx, agentHash)
	if errors.Is(err, index.ErrNotFound) {
		resolveErr := fmt.Errorf("%w: agent address record", ErrNotFound)
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}
	if err != nil {
		resolveErr := fmt.Errorf("get agent address record: %w", err)
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}

	record := indexedRecord.Record
	if err := record.Verify(s.publicKey); err != nil {
		resolveErr := VerificationError{Step: "agent address signature", Err: err}
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}

	payload := record.Payload()
	if payload.AgentIDHash != agentHash {
		resolveErr := VerificationError{Step: "agent id hash", Err: errors.New("record hash does not match requested agent id")}
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}

	pointer, err := s.pointerResolver.ResolveFactsPointer(ctx, payload.FactsPtrHash128)
	if errors.Is(err, facts.ErrNotFound) {
		resolveErr := fmt.Errorf("%w: agent facts pointer", ErrNotFound)
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}
	if err != nil {
		resolveErr := fmt.Errorf("resolve agent facts pointer: %w", err)
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}
	if facts.PointerHash128(pointer) != payload.FactsPtrHash128 {
		resolveErr := VerificationError{Step: "agent facts pointer hash", Err: errors.New("pointer hash does not match agent address payload")}
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}

	factsBytes, err := s.factsStore.Get(ctx, pointer)
	if errors.Is(err, facts.ErrNotFound) {
		resolveErr := fmt.Errorf("%w: agent facts", ErrNotFound)
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}
	if err != nil {
		resolveErr := fmt.Errorf("get agent facts: %w", err)
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}

	var decodedFacts agentfacts.AgentFacts
	if err := json.Unmarshal(factsBytes, &decodedFacts); err != nil {
		resolveErr := ValidationError{Field: "agentFacts", Err: fmt.Errorf("invalid JSON: %w", err)}
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}
	if err := agentfacts.Validate(decodedFacts, agentID, req.RequiredCapability, s.now()); err != nil {
		resolveErr := ValidationError{Field: "agentFacts", Err: err}
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}

	trustDecision := TrustDecisionUnverifiedV0
	capabilityCredentialVerified := false
	if req.RequiredCapability != "" {
		if s.trustVerifier == nil {
			resolveErr := fmt.Errorf("%w: trust verifier is not configured", ErrTrustDenied)
			return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventTrustDenied, resolveErr)
		}
		if err := s.trustVerifier.VerifyCapability(decodedFacts.Credentials, agentID, req.RequiredCapability, s.now()); err != nil {
			resolveErr := fmt.Errorf("%w: %v", ErrTrustDenied, err)
			return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventTrustDenied, resolveErr)
		}
		trustDecision = TrustDecisionVerifiedV0
		capabilityCredentialVerified = true
	}

	endpoint, ok := selectEndpoint(decodedFacts)
	if !ok {
		resolveErr := ValidationError{Field: "endpoints", Err: ErrNoEndpoint}
		return ResolveResponse{}, s.auditResolveFailure(ctx, req, agentID, agentHashHex, audit.EventResolveDenied, resolveErr)
	}

	resp := ResolveResponse{
		AgentID:       agentID,
		Endpoint:      endpoint,
		TrustDecision: trustDecision,
		ProofBundle: ProofBundle{
			AgentAddrSignatureVerified:    true,
			AgentFactsPointerHashVerified: true,
			AgentFactsSchemaVerified:      true,
			CredentialStatus:              CredentialStatusNotImplemented,
			CapabilityCredentialVerified:  capabilityCredentialVerified,
		},
	}
	if err := s.auditResolveSuccess(ctx, req, resp, agentHashHex); err != nil {
		return ResolveResponse{}, err
	}

	return resp, nil
}

func (s *Service) auditResolveSuccess(ctx context.Context, req ResolveRequest, resp ResolveResponse, agentHash string) error {
	if s.auditStore == nil {
		return nil
	}
	payload, err := audit.Payload(map[string]any{
		"request": map[string]any{
			"agentId":            req.AgentID,
			"requiredCapability": req.RequiredCapability,
		},
		"result": map[string]any{
			"agentId":       resp.AgentID,
			"endpointId":    resp.Endpoint.ID,
			"endpointType":  resp.Endpoint.Type,
			"trustDecision": resp.TrustDecision,
			"proofBundle":   resp.ProofBundle,
		},
	})
	if err != nil {
		return fmt.Errorf("build resolve audit payload: %w", err)
	}
	if _, err := s.auditStore.Append(ctx, audit.EventInput{
		EventType: audit.EventResolveAllowed,
		AgentID:   resp.AgentID,
		AgentHash: agentHash,
		Decision:  audit.DecisionAllowed,
		EventJSON: payload,
	}); err != nil {
		return fmt.Errorf("append resolve audit event: %w", err)
	}
	return nil
}

func (s *Service) auditResolveFailure(ctx context.Context, req ResolveRequest, agentID string, agentHash string, eventType string, resolveErr error) error {
	if s.auditStore == nil {
		return resolveErr
	}
	payload, err := audit.Payload(map[string]any{
		"request": map[string]any{
			"agentId":            req.AgentID,
			"requiredCapability": req.RequiredCapability,
		},
		"result": map[string]any{
			"error": resolveErr.Error(),
		},
	})
	if err != nil {
		return fmt.Errorf("build resolve audit payload: %w", err)
	}
	if _, err := s.auditStore.Append(ctx, audit.EventInput{
		EventType: eventType,
		AgentID:   agentID,
		AgentHash: agentHash,
		Decision:  audit.DecisionDenied,
		Reason:    resolveErr.Error(),
		EventJSON: payload,
	}); err != nil {
		return fmt.Errorf("append resolve audit event: %w", err)
	}
	return resolveErr
}

func selectEndpoint(facts agentfacts.AgentFacts) (agentfacts.Endpoint, bool) {
	for _, endpointType := range []string{
		agentfacts.EndpointTypeAdaptiveResolver,
		agentfacts.EndpointTypeRotating,
		agentfacts.EndpointTypeStatic,
	} {
		for _, endpoint := range facts.Endpoints {
			if endpoint.Type == endpointType {
				return endpoint, true
			}
		}
	}

	return agentfacts.Endpoint{}, false
}
