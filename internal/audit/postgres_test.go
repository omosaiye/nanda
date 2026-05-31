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

	page, err := store.Query(ctx, Query{AgentID: "agent.example", Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("query page: %v", err)
	}
	if page.Limit != 1 || page.Offset != 1 || page.Count != 1 {
		t.Fatalf("page = limit %d offset %d count %d, want 1/1/1", page.Limit, page.Offset, page.Count)
	}
	if page.Items[0].EventID != second.EventID {
		t.Fatalf("page event id = %q, want %q", page.Items[0].EventID, second.EventID)
	}

	filtered, err := store.Query(ctx, Query{EventType: EventResolveDenied, Decision: DecisionDenied})
	if err != nil {
		t.Fatalf("query filters: %v", err)
	}
	if filtered.Count != 1 || len(filtered.Items) != 1 {
		t.Fatalf("filtered count/items = %d/%d, want 1/1", filtered.Count, len(filtered.Items))
	}
	if filtered.Items[0].EventID != second.EventID {
		t.Fatalf("filtered event id = %q, want %q", filtered.Items[0].EventID, second.EventID)
	}
}

func TestPostgresAuditEventsAppendOnlyGuardrail(t *testing.T) {
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
	if err := applyAuditAppendOnlyMigration(ctx, db); err != nil {
		t.Fatalf("apply append-only migration: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS audit_events")
		_, _ = db.ExecContext(context.Background(), "DROP FUNCTION IF EXISTS prevent_audit_events_mutation()")
	})

	store, err := NewPostgresStore(db)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	event, err := store.Append(ctx, EventInput{
		EventType: EventAgentRegistered,
		AgentID:   "agent.example",
		AgentHash: "abc123",
		Decision:  DecisionAllowed,
		EventJSON: json.RawMessage(`{"request":{"agentId":"agent.example"},"result":{"agentId":"agent.example"}}`),
	})
	if err != nil {
		t.Fatalf("append event: %v", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE audit_events SET reason = 'changed' WHERE event_id = $1`, event.EventID); err == nil {
		t.Fatal("update audit_events succeeded; want append-only trigger failure")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_events WHERE event_id = $1`, event.EventID); err == nil {
		t.Fatal("delete audit_events succeeded; want append-only trigger failure")
	}
}

func applyAuditTestSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS audit_events"); err != nil {
		return err
	}
	schema, err := os.ReadFile("../../migrations/002_audit_events.sql")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, string(schema))
	return err
}

func applyAuditAppendOnlyMigration(ctx context.Context, db *sql.DB) error {
	schema, err := os.ReadFile("../../migrations/005_audit_events_append_only.sql")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, string(schema))
	return err
}
