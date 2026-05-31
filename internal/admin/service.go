package admin

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/audit"
	"github.com/solai/nanda/internal/index"
	"github.com/solai/nanda/internal/revocation"
)

var (
	ErrValidation             = errors.New("admin validation failed")
	ErrNotFound               = errors.New("admin record not found")
	ErrMissingIndexStore      = errors.New("admin service requires an index store")
	ErrMissingAuditStore      = errors.New("admin service requires an audit store")
	ErrMissingRevocationStore = errors.New("admin service requires a revocation store")
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
	indexStore      index.LeanIndexStore
	auditStore      audit.Store
	revocationStore revocation.Store
}

type AgentResponse struct {
	AgentID          string `json:"agentId"`
	AgentHash        string `json:"agentHash"`
	Sequence         uint32 `json:"sequence"`
	TTLSeconds       uint16 `json:"ttlSeconds"`
	FactsPtrHash128  string `json:"factsPtrHash128"`
	CredentialSet128 string `json:"credentialSet128"`
	RecordBase64     string `json:"recordBase64"`
}

type RevocationStatusResponse struct {
	Issuer       string     `json:"issuer"`
	CredentialID string     `json:"credentialId"`
	Status       string     `json:"status"`
	Reason       string     `json:"reason,omitempty"`
	Found        bool       `json:"found"`
	UpdatedAt    *time.Time `json:"updatedAt,omitempty"`
}

func NewService(indexStore index.LeanIndexStore, auditStore audit.Store, revocationStore revocation.Store) (*Service, error) {
	if indexStore == nil {
		return nil, ErrMissingIndexStore
	}
	if auditStore == nil {
		return nil, ErrMissingAuditStore
	}
	if revocationStore == nil {
		return nil, ErrMissingRevocationStore
	}
	return &Service{
		indexStore:      indexStore,
		auditStore:      auditStore,
		revocationStore: revocationStore,
	}, nil
}

func (s *Service) GetAgent(ctx context.Context, agentID string) (AgentResponse, error) {
	normalizedAgentID, err := agentaddr.NormalizeAgentID(agentID)
	if err != nil {
		return AgentResponse{}, ValidationError{Field: "agentId", Err: err}
	}
	agentHash, err := agentaddr.AgentIDHash(normalizedAgentID)
	if err != nil {
		return AgentResponse{}, ValidationError{Field: "agentId", Err: err}
	}
	record, err := s.indexStore.Get(ctx, agentHash)
	if errors.Is(err, index.ErrNotFound) {
		return AgentResponse{}, fmt.Errorf("%w: agent", ErrNotFound)
	}
	if err != nil {
		return AgentResponse{}, fmt.Errorf("get agent address record: %w", err)
	}

	payload := record.Record.Payload()
	return AgentResponse{
		AgentID:          normalizedAgentID,
		AgentHash:        hex.EncodeToString(agentHash[:]),
		Sequence:         payload.Sequence,
		TTLSeconds:       payload.TTLSeconds,
		FactsPtrHash128:  hex.EncodeToString(payload.FactsPtrHash128[:]),
		CredentialSet128: hex.EncodeToString(payload.CredentialSet128[:]),
		RecordBase64:     base64.StdEncoding.EncodeToString(record.Record.Encode()),
	}, nil
}

func (s *Service) ListAudit(ctx context.Context, query audit.Query) (audit.ListResult, error) {
	result, err := s.auditStore.Query(ctx, query)
	if err != nil {
		if errors.Is(err, audit.ErrInvalidQuery) {
			return audit.ListResult{}, ValidationError{Err: err}
		}
		return audit.ListResult{}, fmt.Errorf("list audit events: %w", err)
	}
	return result, nil
}

func (s *Service) ListAuditByAgent(ctx context.Context, agentID string, query audit.Query) (audit.ListResult, error) {
	normalizedAgentID, err := agentaddr.NormalizeAgentID(agentID)
	if err != nil {
		return audit.ListResult{}, ValidationError{Field: "agentId", Err: err}
	}
	query.AgentID = normalizedAgentID
	result, err := s.auditStore.Query(ctx, query)
	if err != nil {
		if errors.Is(err, audit.ErrInvalidQuery) {
			return audit.ListResult{}, ValidationError{Err: err}
		}
		return audit.ListResult{}, fmt.Errorf("list audit events by agent: %w", err)
	}
	return result, nil
}

func (s *Service) GetRevocationStatus(ctx context.Context, issuer string, credentialID string) (RevocationStatusResponse, error) {
	if issuer == "" {
		return RevocationStatusResponse{}, ValidationError{Field: "issuer", Err: errors.New("issuer is required")}
	}
	if credentialID == "" {
		return RevocationStatusResponse{}, ValidationError{Field: "credentialId", Err: errors.New("credential id is required")}
	}

	record, err := s.revocationStore.GetStatus(ctx, issuer, credentialID)
	if errors.Is(err, revocation.ErrNotFound) {
		return RevocationStatusResponse{
			Issuer:       issuer,
			CredentialID: credentialID,
			Status:       revocation.StatusActive,
			Found:        false,
		}, nil
	}
	if err != nil {
		return RevocationStatusResponse{}, fmt.Errorf("get revocation status: %w", err)
	}

	updatedAt := record.UpdatedAt.UTC()
	return RevocationStatusResponse{
		Issuer:       record.Issuer,
		CredentialID: record.CredentialID,
		Status:       record.Status,
		Reason:       record.Reason,
		Found:        true,
		UpdatedAt:    &updatedAt,
	}, nil
}
