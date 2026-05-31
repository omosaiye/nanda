package facts

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestFilesystemStorePutThenGet(t *testing.T) {
	store, err := NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("new filesystem store: %v", err)
	}
	want := []byte(`{"agent":"agent.example","endpoint":"https://agent.example"}`)

	pointer, err := store.Put(context.Background(), want)
	if err != nil {
		t.Fatalf("put facts: %v", err)
	}
	if pointer.Scheme != filesystemScheme {
		t.Fatalf("pointer scheme = %q, want %q", pointer.Scheme, filesystemScheme)
	}
	if filepath.IsAbs(pointer.Path) {
		t.Fatalf("pointer path = %q, want relative", pointer.Path)
	}

	got, err := store.Get(context.Background(), pointer)
	if err != nil {
		t.Fatalf("get facts: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("facts bytes = %q, want %q", got, want)
	}
}

func TestFilesystemStoreMissingFacts(t *testing.T) {
	store, err := NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("new filesystem store: %v", err)
	}

	_, err = store.Get(context.Background(), FactsPointer{
		Scheme: filesystemScheme,
		Path:   "ab/cd/missing.facts",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing facts error = %v, want %v", err, ErrNotFound)
	}
}

func TestPointerHash128Deterministic(t *testing.T) {
	pointer := FactsPointer{Scheme: filesystemScheme, Path: "ab/cd/facts.facts"}
	a := PointerHash128(pointer)
	b := PointerHash128(pointer)
	c := PointerHash128(FactsPointer{Scheme: filesystemScheme, Path: "other.facts"})

	if a != b {
		t.Fatal("same pointer produced different hashes")
	}
	if a == c {
		t.Fatal("different pointers produced the same hash")
	}
}
