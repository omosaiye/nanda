package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
)

func TestLoadLocalDefaultsAndEphemeralKey(t *testing.T) {
	cfg, err := LoadLocal(func(string) string { return "" })
	if err != nil {
		t.Fatalf("load local: %v", err)
	}
	if cfg.Addr != ":8080" {
		t.Fatalf("addr = %q, want :8080", cfg.Addr)
	}
	if cfg.FactsDir != "./var/facts" {
		t.Fatalf("facts dir = %q, want ./var/facts", cfg.FactsDir)
	}
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("private key length = %d", len(cfg.PrivateKey))
	}
	if len(cfg.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d", len(cfg.PublicKey))
	}
	if !cfg.EphemeralKey {
		t.Fatal("missing private key should generate an ephemeral key")
	}
}

func TestLoadLocalConfiguredKeyPair(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	values := map[string]string{
		"NANDA_ADDR":               ":9090",
		"NANDA_POSTGRES_DSN":       "postgres://example",
		"NANDA_FACTS_DIR":          "/tmp/facts",
		"NANDA_PRIVATE_KEY_BASE64": base64.StdEncoding.EncodeToString(privateKey),
		"NANDA_PUBLIC_KEY_BASE64":  base64.StdEncoding.EncodeToString(publicKey),
	}

	cfg, err := LoadLocal(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("load local: %v", err)
	}
	if cfg.Addr != ":9090" || cfg.PostgresDSN != "postgres://example" || cfg.FactsDir != "/tmp/facts" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.EphemeralKey {
		t.Fatal("configured private key should not be marked ephemeral")
	}
}

func TestLoadLocalRejectsMismatchedPublicKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate public key: %v", err)
	}
	values := map[string]string{
		"NANDA_PRIVATE_KEY_BASE64": base64.StdEncoding.EncodeToString(privateKey),
		"NANDA_PUBLIC_KEY_BASE64":  base64.StdEncoding.EncodeToString(publicKey),
	}

	_, err = LoadLocal(func(key string) string { return values[key] })
	if !errors.Is(err, ErrInvalidKeyConfig) {
		t.Fatalf("load local error = %v, want %v", err, ErrInvalidKeyConfig)
	}
}
