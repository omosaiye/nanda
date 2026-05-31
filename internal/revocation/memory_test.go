package revocation

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreStatusLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	store.now = func() time.Time { return time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC) }

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
	revoked, err = store.IsRevoked(ctx, "did:example:issuer", "credential-1")
	if err != nil {
		t.Fatalf("is revoked active: %v", err)
	}
	if revoked {
		t.Fatal("active credential was treated as revoked")
	}

	if err := store.SetStatus(ctx, "did:example:issuer", "credential-1", StatusRevoked, "key rotated"); err != nil {
		t.Fatalf("set revoked: %v", err)
	}
	record, err = store.GetStatus(ctx, "did:example:issuer", "credential-1")
	if err != nil {
		t.Fatalf("get revoked: %v", err)
	}
	if record.Status != StatusRevoked {
		t.Fatalf("status = %q, want %q", record.Status, StatusRevoked)
	}
	if record.Reason != "key rotated" {
		t.Fatalf("reason = %q, want key rotated", record.Reason)
	}
	revoked, err = store.IsRevoked(ctx, "did:example:issuer", "credential-1")
	if err != nil {
		t.Fatalf("is revoked revoked: %v", err)
	}
	if !revoked {
		t.Fatal("revoked credential was not treated as revoked")
	}
}

func TestMemoryStoreInvalidInput(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "empty issuer set",
			err:  store.SetStatus(ctx, "", "credential-1", StatusRevoked, ""),
		},
		{
			name: "empty credential id set",
			err:  store.SetStatus(ctx, "did:example:issuer", "", StatusRevoked, ""),
		},
		{
			name: "invalid status",
			err:  store.SetStatus(ctx, "did:example:issuer", "credential-1", "unknown", ""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, ErrInvalidInput) {
				t.Fatalf("error = %v, want %v", tt.err, ErrInvalidInput)
			}
		})
	}

	if _, err := store.GetStatus(ctx, "", "credential-1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("get invalid error = %v, want %v", err, ErrInvalidInput)
	}
	if _, err := store.IsRevoked(ctx, "did:example:issuer", ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("is revoked invalid error = %v, want %v", err, ErrInvalidInput)
	}
}
