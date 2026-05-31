package revocation

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresStore(t *testing.T) {
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
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS credential_revocations"); err != nil {
		t.Fatalf("reset test schema: %v", err)
	}
	if err := applyRevocationTestSchema(ctx, db); err != nil {
		t.Fatalf("apply test schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS credential_revocations")
	})

	store, err := NewPostgresStore(db)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}

	revoked, err := store.IsRevoked(ctx, "did:example:issuer", "credential-1")
	if err != nil {
		t.Fatalf("is revoked missing: %v", err)
	}
	if revoked {
		t.Fatal("missing revocation record was treated as revoked")
	}
	if _, err := store.GetStatus(ctx, "did:example:issuer", "credential-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing error = %v, want %v", err, ErrNotFound)
	}

	if err := store.SetStatus(ctx, "did:example:issuer", "credential-1", StatusActive, ""); err != nil {
		t.Fatalf("set active: %v", err)
	}
	record, err := store.GetStatus(ctx, "did:example:issuer", "credential-1")
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if record.Status != StatusActive {
		t.Fatalf("status = %q, want %q", record.Status, StatusActive)
	}
	if record.UpdatedAt.IsZero() {
		t.Fatal("updated at was not set")
	}

	if err := store.SetStatus(ctx, "did:example:issuer", "credential-1", StatusRevoked, "compromised"); err != nil {
		t.Fatalf("set revoked: %v", err)
	}
	record, err = store.GetStatus(ctx, "did:example:issuer", "credential-1")
	if err != nil {
		t.Fatalf("get revoked: %v", err)
	}
	if record.Status != StatusRevoked {
		t.Fatalf("status = %q, want %q", record.Status, StatusRevoked)
	}
	if record.Reason != "compromised" {
		t.Fatalf("reason = %q, want compromised", record.Reason)
	}
	revoked, err = store.IsRevoked(ctx, "did:example:issuer", "credential-1")
	if err != nil {
		t.Fatalf("is revoked: %v", err)
	}
	if !revoked {
		t.Fatal("revoked credential was not treated as revoked")
	}

	if err := store.SetStatus(ctx, "did:example:issuer", "credential-1", "unknown", ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid set error = %v, want %v", err, ErrInvalidInput)
	}
}

func applyRevocationTestSchema(ctx context.Context, db *sql.DB) error {
	schema, err := os.ReadFile("../../migrations/003_credential_revocations.sql")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, string(schema))
	return err
}
