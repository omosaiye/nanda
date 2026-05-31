package facts

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresPointerStore(t *testing.T) {
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
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS facts_pointers"); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	schema, err := os.ReadFile("../../migrations/004_facts_pointers.sql")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS facts_pointers")
	})

	store, err := NewPostgresPointerStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	pointer := FactsPointer{Scheme: "fs", Path: "ab/cd/agent.facts"}
	hash := PointerHash128(pointer)

	if _, err := store.ResolveFactsPointer(ctx, hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing pointer error = %v, want %v", err, ErrNotFound)
	}
	if err := store.PutFactsPointer(ctx, pointer); err != nil {
		t.Fatalf("put pointer: %v", err)
	}
	got, err := store.ResolveFactsPointer(ctx, hash)
	if err != nil {
		t.Fatalf("resolve pointer: %v", err)
	}
	if got != pointer {
		t.Fatalf("pointer = %+v, want %+v", got, pointer)
	}
}
