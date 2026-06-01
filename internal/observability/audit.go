package observability

import (
	"context"

	"github.com/solai/nanda/internal/audit"
)

type AuditStore struct {
	next     audit.Store
	registry *Registry
}

func NewAuditStore(next audit.Store, registry *Registry) audit.Store {
	if next == nil {
		return nil
	}
	return &AuditStore{next: next, registry: registry}
}

func (s *AuditStore) Append(ctx context.Context, input audit.EventInput) (audit.Event, error) {
	event, err := s.next.Append(ctx, input)
	if err != nil {
		return audit.Event{}, err
	}
	if s.registry != nil {
		s.registry.IncAuditEvents(event.EventType, event.Decision)
	}
	return event, nil
}

func (s *AuditStore) List(ctx context.Context) ([]audit.Event, error) {
	return s.next.List(ctx)
}

func (s *AuditStore) ListByAgent(ctx context.Context, agentID string) ([]audit.Event, error) {
	return s.next.ListByAgent(ctx, agentID)
}

func (s *AuditStore) Query(ctx context.Context, query audit.Query) (audit.ListResult, error) {
	return s.next.Query(ctx, query)
}

func (s *AuditStore) VerifyHashChain(ctx context.Context) error {
	return s.next.VerifyHashChain(ctx)
}
