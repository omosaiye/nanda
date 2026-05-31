package audit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreAppendListAndVerifyHashChain(t *testing.T) {
	store := NewMemoryStore()
	store.now = fixedNow
	ctx := context.Background()

	first, err := store.Append(ctx, EventInput{
		EventType: EventAgentRegistered,
		AgentID:   "agent.example",
		AgentHash: "abc123",
		Decision:  DecisionAllowed,
		EventJSON: json.RawMessage(`{"result":{"agentId":"agent.example"},"request":{"agentId":"Agent.Example"}}`),
	})
	if err != nil {
		t.Fatalf("append first: %v", err)
	}
	second, err := store.Append(ctx, EventInput{
		EventType: EventResolveAllowed,
		AgentID:   "agent.example",
		AgentHash: "abc123",
		Decision:  DecisionAllowed,
		EventJSON: json.RawMessage(`{"request":{"agentId":"agent.example"},"result":{"endpointId":"static"}}`),
	})
	if err != nil {
		t.Fatalf("append second: %v", err)
	}

	if first.PreviousHash != "" {
		t.Fatalf("first previous hash = %q, want empty", first.PreviousHash)
	}
	if second.PreviousHash != first.EventHash {
		t.Fatalf("second previous hash = %q, want %q", second.PreviousHash, first.EventHash)
	}
	if first.EventHash == "" || second.EventHash == "" || first.EventHash == second.EventHash {
		t.Fatalf("unexpected event hashes first=%q second=%q", first.EventHash, second.EventHash)
	}
	if err := store.VerifyHashChain(ctx); err != nil {
		t.Fatalf("verify hash chain: %v", err)
	}

	events, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("list length = %d, want 2", len(events))
	}
	events[0].Reason = "tampered copy"
	if err := store.VerifyHashChain(ctx); err != nil {
		t.Fatalf("list returned mutable event backing store: %v", err)
	}

	agentEvents, err := store.ListByAgent(ctx, "agent.example")
	if err != nil {
		t.Fatalf("list by agent: %v", err)
	}
	if len(agentEvents) != 2 {
		t.Fatalf("agent event count = %d, want 2", len(agentEvents))
	}
}

func TestMemoryStoreVerifyHashChainDetectsTampering(t *testing.T) {
	store := NewMemoryStore()
	store.now = fixedNow
	ctx := context.Background()

	if _, err := store.Append(ctx, EventInput{
		EventType: EventTrustDenied,
		AgentID:   "agent.example",
		Decision:  DecisionDenied,
		Reason:    "credential trust denied",
		EventJSON: json.RawMessage(`{"request":{"agentId":"agent.example"},"result":{"error":"denied"}}`),
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	store.events[0].Reason = "changed"
	if err := store.VerifyHashChain(ctx); !errors.Is(err, ErrHashChainInvalid) {
		t.Fatalf("verify error = %v, want %v", err, ErrHashChainInvalid)
	}
}

func TestMemoryStoreHashVerificationSurvivesNonCanonicalEventJSON(t *testing.T) {
	store := NewMemoryStore()
	store.now = fixedNow
	ctx := context.Background()

	event, err := store.Append(ctx, EventInput{
		EventType: EventAgentRegistered,
		AgentID:   "agent.example",
		AgentHash: "abc123",
		Decision:  DecisionAllowed,
		EventJSON: json.RawMessage(`{"b":2,"a":1}`),
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if string(event.EventJSON) != `{"a":1,"b":2}` {
		t.Fatalf("event JSON = %s, want canonical JSON", event.EventJSON)
	}
	if err := store.VerifyHashChain(ctx); err != nil {
		t.Fatalf("verify canonical hash chain: %v", err)
	}

	store.events[0].EventJSON = json.RawMessage(`{"b":2,"a":1}`)
	if err := store.VerifyHashChain(ctx); err != nil {
		t.Fatalf("verify hash chain with non-canonical stored JSON: %v", err)
	}
}

func TestMemoryStoreQueryDefaultPagination(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	for i := 0; i < DefaultListLimit+1; i++ {
		appendMemoryAuditEvent(t, store, EventAgentRegistered, "agent.example", DecisionAllowed)
	}

	result, err := store.Query(ctx, Query{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if result.Limit != DefaultListLimit || result.Offset != 0 || result.Count != DefaultListLimit {
		t.Fatalf("result page = limit %d offset %d count %d, want %d/0/%d", result.Limit, result.Offset, result.Count, DefaultListLimit, DefaultListLimit)
	}
	if len(result.Items) != DefaultListLimit {
		t.Fatalf("items length = %d, want %d", len(result.Items), DefaultListLimit)
	}
}

func TestMemoryStoreQueryLimitOffset(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	first := appendMemoryAuditEvent(t, store, EventAgentRegistered, "agent.example", DecisionAllowed)
	second := appendMemoryAuditEvent(t, store, EventResolveAllowed, "agent.example", DecisionAllowed)
	appendMemoryAuditEvent(t, store, EventResolveDenied, "agent.example", DecisionDenied)

	result, err := store.Query(ctx, Query{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if result.Count != 1 || len(result.Items) != 1 {
		t.Fatalf("count/items = %d/%d, want 1/1", result.Count, len(result.Items))
	}
	if result.Items[0].EventID != second.EventID || result.Items[0].EventID == first.EventID {
		t.Fatalf("event id = %q, want second %q", result.Items[0].EventID, second.EventID)
	}
}

func TestMemoryStoreQueryFilters(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	registered := appendMemoryAuditEvent(t, store, EventAgentRegistered, "agent.example", DecisionAllowed)
	denied := appendMemoryAuditEvent(t, store, EventResolveDenied, "agent.example", DecisionDenied)
	other := appendMemoryAuditEvent(t, store, EventResolveAllowed, "other.example", DecisionAllowed)

	tests := []struct {
		name  string
		query Query
		want  string
	}{
		{name: "event type", query: Query{EventType: EventResolveDenied}, want: denied.EventID},
		{name: "decision", query: Query{Decision: DecisionDenied}, want: denied.EventID},
		{name: "agent", query: Query{AgentID: "other.example"}, want: other.EventID},
		{name: "combined", query: Query{AgentID: "agent.example", EventType: EventAgentRegistered, Decision: DecisionAllowed}, want: registered.EventID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := store.Query(ctx, tt.query)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if result.Count != 1 || len(result.Items) != 1 {
				t.Fatalf("count/items = %d/%d, want 1/1", result.Count, len(result.Items))
			}
			if result.Items[0].EventID != tt.want {
				t.Fatalf("event id = %q, want %q", result.Items[0].EventID, tt.want)
			}
		})
	}
}

func TestMemoryStoreQueryValidation(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	tests := []struct {
		name  string
		query Query
	}{
		{name: "invalid event type", query: Query{EventType: "unknown"}},
		{name: "invalid decision", query: Query{Decision: "unknown"}},
		{name: "negative offset", query: Query{Offset: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.Query(ctx, tt.query)
			if !errors.Is(err, ErrInvalidQuery) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidQuery)
			}
		})
	}
}

func TestCanonicalJSONDeterministic(t *testing.T) {
	first, err := CanonicalJSON(json.RawMessage(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatalf("canonical first: %v", err)
	}
	second, err := CanonicalJSON(json.RawMessage(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatalf("canonical second: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("canonical JSON differs: %s vs %s", first, second)
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
}

func appendMemoryAuditEvent(t *testing.T, store *MemoryStore, eventType string, agentID string, decision string) Event {
	t.Helper()
	event, err := store.Append(context.Background(), EventInput{
		EventType: eventType,
		AgentID:   agentID,
		Decision:  decision,
		EventJSON: json.RawMessage(`{"ok":true}`),
	})
	if err != nil {
		t.Fatalf("append audit event: %v", err)
	}
	return event
}
