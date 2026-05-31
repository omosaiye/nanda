package audit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type MemoryStore struct {
	mu     sync.Mutex
	events []Event
	now    func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{now: time.Now}
}

func (s *MemoryStore) Append(_ context.Context, input EventInput) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	previousHash := ""
	if len(s.events) > 0 {
		previousHash = s.events[len(s.events)-1].EventHash
	}
	now := s.now
	if now == nil {
		now = time.Now
	}
	event, err := NewEvent(previousHash, input, now())
	if err != nil {
		return Event{}, err
	}
	s.events = append(s.events, event)
	return event, nil
}

func (s *MemoryStore) List(_ context.Context) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return copyEvents(s.events), nil
}

func (s *MemoryStore) ListByAgent(_ context.Context, agentID string) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var events []Event
	for _, event := range s.events {
		if event.AgentID == agentID {
			events = append(events, event)
		}
	}
	return copyEvents(events), nil
}

func (s *MemoryStore) VerifyHashChain(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return verifyEvents(s.events)
}

func verifyEvents(events []Event) error {
	previousHash := ""
	for i, event := range events {
		if event.PreviousHash != previousHash {
			return fmt.Errorf("%w: event %d previous hash mismatch", ErrHashChainInvalid, i)
		}
		gotHash, err := HashEvent(previousHash, event)
		if err != nil {
			return err
		}
		if event.EventHash != gotHash {
			return fmt.Errorf("%w: event %d hash mismatch", ErrHashChainInvalid, i)
		}
		previousHash = event.EventHash
	}
	return nil
}

func copyEvents(events []Event) []Event {
	copied := make([]Event, len(events))
	for i, event := range events {
		copied[i] = event
		copied[i].EventJSON = append([]byte(nil), event.EventJSON...)
	}
	return copied
}
