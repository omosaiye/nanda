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
	"github.com/solai/nanda/internal/facts"
	"github.com/solai/nanda/internal/index"
)

const (
	TrustDecisionUnverifiedV0      = "unverified-v0"
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

type Service struct {
	indexStore      index.LeanIndexStore
	factsStore      facts.FactsStore
	pointerResolver FactsPointerResolver
	publicKey       ed25519.PublicKey
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
}

func NewService(indexStore index.LeanIndexStore, factsStore facts.FactsStore, pointerResolver FactsPointerResolver, publicKey ed25519.PublicKey) (*Service, error) {
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

	return &Service{
		indexStore:      indexStore,
		factsStore:      factsStore,
		pointerResolver: pointerResolver,
		publicKey:       publicKey,
		now:             time.Now,
	}, nil
}

func (s *Service) Resolve(ctx context.Context, req ResolveRequest) (ResolveResponse, error) {
	agentID, err := agentaddr.NormalizeAgentID(req.AgentID)
	if err != nil {
		return ResolveResponse{}, ValidationError{Field: "agentId", Err: err}
	}

	agentHash, err := agentaddr.AgentIDHash(agentID)
	if err != nil {
		return ResolveResponse{}, ValidationError{Field: "agentId", Err: err}
	}

	indexedRecord, err := s.indexStore.Get(ctx, agentHash)
	if errors.Is(err, index.ErrNotFound) {
		return ResolveResponse{}, fmt.Errorf("%w: agent address record", ErrNotFound)
	}
	if err != nil {
		return ResolveResponse{}, fmt.Errorf("get agent address record: %w", err)
	}

	record := indexedRecord.Record
	if err := record.Verify(s.publicKey); err != nil {
		return ResolveResponse{}, VerificationError{Step: "agent address signature", Err: err}
	}

	payload := record.Payload()
	if payload.AgentIDHash != agentHash {
		return ResolveResponse{}, VerificationError{Step: "agent id hash", Err: errors.New("record hash does not match requested agent id")}
	}

	pointer, err := s.pointerResolver.ResolveFactsPointer(ctx, payload.FactsPtrHash128)
	if errors.Is(err, facts.ErrNotFound) {
		return ResolveResponse{}, fmt.Errorf("%w: agent facts pointer", ErrNotFound)
	}
	if err != nil {
		return ResolveResponse{}, fmt.Errorf("resolve agent facts pointer: %w", err)
	}
	if facts.PointerHash128(pointer) != payload.FactsPtrHash128 {
		return ResolveResponse{}, VerificationError{Step: "agent facts pointer hash", Err: errors.New("pointer hash does not match agent address payload")}
	}

	factsBytes, err := s.factsStore.Get(ctx, pointer)
	if errors.Is(err, facts.ErrNotFound) {
		return ResolveResponse{}, fmt.Errorf("%w: agent facts", ErrNotFound)
	}
	if err != nil {
		return ResolveResponse{}, fmt.Errorf("get agent facts: %w", err)
	}

	var decodedFacts agentfacts.AgentFacts
	if err := json.Unmarshal(factsBytes, &decodedFacts); err != nil {
		return ResolveResponse{}, ValidationError{Field: "agentFacts", Err: fmt.Errorf("invalid JSON: %w", err)}
	}
	if err := agentfacts.Validate(decodedFacts, agentID, req.RequiredCapability, s.now()); err != nil {
		return ResolveResponse{}, ValidationError{Field: "agentFacts", Err: err}
	}

	endpoint, ok := selectEndpoint(decodedFacts)
	if !ok {
		return ResolveResponse{}, ValidationError{Field: "endpoints", Err: ErrNoEndpoint}
	}

	return ResolveResponse{
		AgentID:       agentID,
		Endpoint:      endpoint,
		TrustDecision: TrustDecisionUnverifiedV0,
		ProofBundle: ProofBundle{
			AgentAddrSignatureVerified:    true,
			AgentFactsPointerHashVerified: true,
			AgentFactsSchemaVerified:      true,
			CredentialStatus:              CredentialStatusNotImplemented,
		},
	}, nil
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
