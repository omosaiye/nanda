package registration

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/facts"
	"github.com/solai/nanda/internal/index"
)

var (
	ErrValidation        = errors.New("registration validation failed")
	ErrMissingFactsStore = errors.New("registration service requires a facts store")
	ErrMissingIndexStore = errors.New("registration service requires an index store")
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

type Service struct {
	factsStore facts.FactsStore
	indexStore index.LeanIndexStore
	privateKey ed25519.PrivateKey
}

type RegisterRequest struct {
	AgentID    string          `json:"agentId"`
	TTLSeconds uint16          `json:"ttlSeconds"`
	Flags      uint8           `json:"flags,omitempty"`
	Sequence   uint32          `json:"sequence"`
	Facts      json.RawMessage `json:"facts"`
}

type RegisterResponse struct {
	AgentID               string `json:"agentId"`
	FactsPointer          string `json:"factsPointer"`
	FactsPtrHash128       string `json:"factsPtrHash128"`
	CredentialSet128      string `json:"credentialSet128"`
	Sequence              uint32 `json:"sequence"`
	TTLSeconds            uint16 `json:"ttlSeconds"`
	AgentAddrRecordBase64 string `json:"agentAddrRecordBase64"`
}

func NewService(factsStore facts.FactsStore, indexStore index.LeanIndexStore, privateKey ed25519.PrivateKey) (*Service, error) {
	if factsStore == nil {
		return nil, ErrMissingFactsStore
	}
	if indexStore == nil {
		return nil, ErrMissingIndexStore
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, agentaddr.ErrInvalidPrivateKey
	}

	return &Service{
		factsStore: factsStore,
		indexStore: indexStore,
		privateKey: privateKey,
	}, nil
}

func (s *Service) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error) {
	agentID, err := validateRegisterRequest(req)
	if err != nil {
		return RegisterResponse{}, err
	}

	pointer, err := s.factsStore.Put(ctx, []byte(req.Facts))
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("store agent facts: %w", err)
	}

	factsPtrHash128 := facts.PointerHash128(pointer)
	// Placeholder until v0 credential extraction and VC verification are introduced.
	credentialSet128 := agentaddr.Hash128([]byte{})

	payload, err := agentaddr.New(agentID, req.TTLSeconds, req.Flags, req.Sequence, factsPtrHash128, credentialSet128)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("create agent address payload: %w", err)
	}

	record, err := agentaddr.Sign(payload, s.privateKey)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("sign agent address record: %w", err)
	}

	if err := s.indexStore.Put(ctx, agentID, record); err != nil {
		return RegisterResponse{}, fmt.Errorf("store agent address record: %w", err)
	}

	return RegisterResponse{
		AgentID:               agentID,
		FactsPointer:          pointer.String(),
		FactsPtrHash128:       hex.EncodeToString(factsPtrHash128[:]),
		CredentialSet128:      hex.EncodeToString(credentialSet128[:]),
		Sequence:              req.Sequence,
		TTLSeconds:            req.TTLSeconds,
		AgentAddrRecordBase64: base64.StdEncoding.EncodeToString(record.Encode()),
	}, nil
}

func validateRegisterRequest(req RegisterRequest) (string, error) {
	agentID, err := agentaddr.NormalizeAgentID(req.AgentID)
	if err != nil {
		return "", ValidationError{Field: "agentId", Err: err}
	}
	if req.TTLSeconds == 0 {
		return "", ValidationError{Field: "ttlSeconds", Err: agentaddr.ErrZeroTTL}
	}
	if !json.Valid(req.Facts) {
		return "", ValidationError{Field: "facts", Err: errors.New("must be valid JSON")}
	}

	return agentID, nil
}
