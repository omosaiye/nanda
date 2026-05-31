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
	if err := dropTestSchema(ctx, db); err != nil {
		t.Fatalf("drop existing test schema: %v", err)
	}
	if err := applyTestSchema(ctx, db); err != nil {
		t.Fatalf("apply test schema: %v", err)
	}
	t.Cleanup(func() {
		_ = dropTestSchema(context.Background(), db)
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

	lower := testRecord(t, agentID, 1)
	if err := store.Put(ctx, agentID, lower); !errors.Is(err, ErrStaleSequence) {
		t.Fatalf("put lower sequence error = %v, want %v", err, ErrStaleSequence)
	}
	got, err = store.Get(ctx, agentHash)
	if err != nil {
		t.Fatalf("get after lower sequence: %v", err)
	}
	if !bytes.Equal(got.Record.Encode(), second.Encode()) {
		t.Fatal("lower sequence changed current record")
	}

	if err := store.Put(ctx, agentID, second); err != nil {
		t.Fatalf("put equal sequence same record: %v", err)
	}
	history, err = store.History(ctx, agentHash)
	if err != nil {
		t.Fatalf("history after idempotent put: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("history length after idempotent put = %d, want 1", len(history))
	}

	equalDifferent := testRecord(t, agentID, 2)
	if err := store.Put(ctx, agentID, equalDifferent); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("put equal sequence different record error = %v, want %v", err, ErrSequenceConflict)
	}
	got, err = store.Get(ctx, agentHash)
	if err != nil {
		t.Fatalf("get after equal sequence conflict: %v", err)
	}
	if !bytes.Equal(got.Record.Encode(), second.Encode()) {
		t.Fatal("equal sequence conflict changed current record")
	}

	third := testRecord(t, agentID, 3)
	if err := store.Put(ctx, agentID, third); err != nil {
		t.Fatalf("put third record: %v", err)
	}
	got, err = store.Get(ctx, agentHash)
	if err != nil {
		t.Fatalf("get third record: %v", err)
	}
	if !bytes.Equal(got.Record.Encode(), third.Encode()) {
		t.Fatal("got record bytes differ from third record")
	}
	history, err = store.History(ctx, agentHash)
	if err != nil {
		t.Fatalf("history after third put: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history length after third put = %d, want 2", len(history))
	}
	if !bytes.Equal(history[1].Record.Encode(), second.Encode()) {
		t.Fatal("history did not include second record after third put")
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

func dropTestSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS agent_addr_history")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "DROP TABLE IF EXISTS agent_addr_records")
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
