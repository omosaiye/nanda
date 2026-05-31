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
