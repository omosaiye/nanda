package tests

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/facts"
)

func TestAgentAddr120BindsToStoredAgentFactsPointerHash(t *testing.T) {
	ctx := context.Background()
	store, err := facts.NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("new filesystem store: %v", err)
	}

	pointer, err := store.Put(ctx, []byte(`{"agent":"agent.example","endpoint":"https://agent.example"}`))
	if err != nil {
		t.Fatalf("put facts: %v", err)
	}
	factsPtrHash := facts.PointerHash128(pointer)

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload, err := agentaddr.New(
		"agent.example",
		300,
		0,
		1,
		factsPtrHash,
		agentaddr.Hash128([]byte("credential set")),
	)
	if err != nil {
		t.Fatalf("new payload: %v", err)
	}

	record, err := agentaddr.Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	decoded, err := agentaddr.Decode(record.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Payload().FactsPtrHash128 != factsPtrHash {
		t.Fatalf("facts ptr hash = %x, want %x", decoded.Payload().FactsPtrHash128, factsPtrHash)
	}
}
