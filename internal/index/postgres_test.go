package index

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/solai/nanda/internal/agentaddr"
)

func TestPostgresLeanIndexStore(t *testing.T) {
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
	if err := applyTestSchema(ctx, db); err != nil {
		t.Fatalf("apply test schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS agent_addr_history, agent_addr_records")
	})

	store, err := NewPostgresStore(db)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	agentID := "agent.example"
	agentHash, err := agentaddr.AgentIDHash(agentID)
	if err != nil {
		t.Fatalf("agent id hash: %v", err)
	}

	t.Run("missing record returns not found", func(t *testing.T) {
		_, err := store.Get(ctx, agentaddr.Hash128([]byte("missing")))
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("get missing error = %v, want %v", err, ErrNotFound)
		}
	})

	first := testRecord(t, agentID, 1)
	if err := store.Put(ctx, agentID, first); err != nil {
		t.Fatalf("put first record: %v", err)
	}
	got, err := store.Get(ctx, agentHash)
	if err != nil {
		t.Fatalf("get first record: %v", err)
	}
	if !bytes.Equal(got.Record.Encode(), first.Encode()) {
		t.Fatal("got record bytes differ from first record")
	}

	second := testRecord(t, agentID, 2)
	if err := store.Put(ctx, agentID, second); err != nil {
		t.Fatalf("put second record: %v", err)
	}
	got, err = store.Get(ctx, agentHash)
	if err != nil {
		t.Fatalf("get second record: %v", err)
	}
	if !bytes.Equal(got.Record.Encode(), second.Encode()) {
		t.Fatal("got record bytes differ from second record")
	}

	history, err := store.History(ctx, agentHash)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("history length = %d, want 1", len(history))
	}
	if !bytes.Equal(history[0].Record.Encode(), first.Encode()) {
		t.Fatal("history did not include prior record")
	}
}

func applyTestSchema(ctx context.Context, db *sql.DB) error {
	schema, err := os.ReadFile("../../migrations/001_agent_addr_index.sql")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, string(schema))
	return err
}

func testRecord(t *testing.T, agentID string, sequence uint32) agentaddr.AgentAddr120 {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload, err := agentaddr.New(
		agentID,
		300,
		0,
		sequence,
		agentaddr.Hash128([]byte("facts")),
		agentaddr.Hash128([]byte("credentials")),
	)
	if err != nil {
		t.Fatalf("new payload: %v", err)
	}
	record, err := agentaddr.Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}

	return record
}
