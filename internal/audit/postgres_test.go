package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresAuditStore(t *testing.T) {
	dsn := os.Getenv("NANDA_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set NANDA_POSTGRES_DSN to run PostgreSQL integration tests")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	if err := applyAuditTestSchema(ctx, db); err != nil {
		t.Fatalf("apply test schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS audit_events")
	})

	store, err := NewPostgresStore(db)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	first, err := store.Append(ctx, EventInput{
		EventType: EventAgentRegistered,
		AgentID:   "agent.example",
		AgentHash: "abc123",
		Decision:  DecisionAllowed,
		EventJSON: json.RawMessage(`{"request":{"agentId":"agent.example"},"result":{"agentId":"agent.example"}}`),
	})
	if err != nil {
		t.Fatalf("append first: %v", err)
	}
	second, err := store.Append(ctx, EventInput{
		EventType: EventResolveDenied,
		AgentID:   "agent.example",
		AgentHash: "abc123",
		Decision:  DecisionDenied,
		Reason:    "not found",
		EventJSON: json.RawMessage(`{"request":{"agentId":"agent.example"},"result":{"error":"not found"}}`),
	})
	if err != nil {
		t.Fatalf("append second: %v", err)
	}
	if second.PreviousHash != first.EventHash {
		t.Fatalf("second previous hash = %q, want %q", second.PreviousHash, first.EventHash)
	}
	if err := store.VerifyHashChain(ctx); err != nil {
		t.Fatalf("verify hash chain: %v", err)
	}

	events, err := store.ListByAgent(ctx, "agent.example")
	if err != nil {
		t.Fatalf("list by agent: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
}

func applyAuditTestSchema(ctx context.Context, db *sql.DB) error {
	schema, err := os.ReadFile("../../migrations/002_audit_events.sql")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, string(schema))
	return err
}
