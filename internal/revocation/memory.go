package revocation

import (
	"context"
	"errors"
	"sync"
	"time"
)

type MemoryStore struct {
	mu      sync.Mutex
	records map[recordKey]Record
	now     func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records: make(map[recordKey]Record),
		now:     time.Now,
	}
}

func (s *MemoryStore) SetStatus(_ context.Context, issuer string, credentialID string, status string, reason string) error {
	if err := validateKey(issuer, credentialID); err != nil {
		return err
	}
	if err := validateStatus(status); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now
	if now == nil {
		now = time.Now
	}
	if s.records == nil {
		s.records = make(map[recordKey]Record)
	}
	s.records[recordKey{issuer: issuer, credentialID: credentialID}] = Record{
		Issuer:       issuer,
		CredentialID: credentialID,
		Status:       status,
		Reason:       reason,
		UpdatedAt:    now().UTC(),
	}
	return nil
}

func (s *MemoryStore) GetStatus(_ context.Context, issuer string, credentialID string) (Record, error) {
	if err := validateKey(issuer, credentialID); err != nil {
		return Record{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[recordKey{issuer: issuer, credentialID: credentialID}]
	if !ok {
		return Record{}, ErrNotFound
	}
	return record, nil
}

func (s *MemoryStore) IsRevoked(ctx context.Context, issuer string, credentialID string) (bool, error) {
	record, err := s.GetStatus(ctx, issuer, credentialID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return record.Status == StatusRevoked, nil
}

type recordKey struct {
	issuer       string
	credentialID string
}
