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
	if cfg.Mode != ModeLocal {
		t.Fatalf("mode = %q, want %q", cfg.Mode, ModeLocal)
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
	if !cfg.AutoMigrate {
		t.Fatal("local mode should auto-migrate by default")
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

func TestLoadLocalProductionConfig(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	values := map[string]string{
		"NANDA_MODE":               ModeProduction,
		"NANDA_POSTGRES_DSN":       "postgres://example",
		"NANDA_PRIVATE_KEY_BASE64": base64.StdEncoding.EncodeToString(privateKey),
		"NANDA_PUBLIC_KEY_BASE64":  base64.StdEncoding.EncodeToString(publicKey),
		"NANDA_API_TOKEN":          "secret",
	}

	cfg, err := LoadLocal(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("load production config: %v", err)
	}
	if err := ValidateRuntime(cfg); err != nil {
		t.Fatalf("validate production config: %v", err)
	}
	if cfg.Mode != ModeProduction {
		t.Fatalf("mode = %q, want %q", cfg.Mode, ModeProduction)
	}
	if cfg.EphemeralKey {
		t.Fatal("production config should not use ephemeral key")
	}
	if cfg.AutoMigrate {
		t.Fatal("production mode should not auto-migrate by default")
	}
}

func TestLoadLocalRejectsInvalidMode(t *testing.T) {
	_, err := LoadLocal(func(key string) string {
		if key == "NANDA_MODE" {
			return "staging"
		}
		return ""
	})
	if !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("load local error = %v, want %v", err, ErrInvalidMode)
	}
}

func TestLoadLocalProductionRequiresPrivateKey(t *testing.T) {
	_, err := LoadLocal(func(key string) string {
		if key == "NANDA_MODE" {
			return ModeProduction
		}
		return ""
	})
	if err == nil {
		t.Fatal("load production config without private key succeeded")
	}
}

func TestValidateRuntimeProductionRequiresPostgresAndToken(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cfg := Local{
		Mode:       ModeProduction,
		PrivateKey: privateKey,
	}

	if err := ValidateRuntime(cfg); err == nil {
		t.Fatal("validate production config without DSN succeeded")
	}

	cfg.PostgresDSN = "postgres://example"
	if err := ValidateRuntime(cfg); err == nil {
		t.Fatal("validate production config without API token succeeded")
	}
}

func TestAutoMigrateModeDefaults(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{
			name: "local default enables migrations",
			env:  map[string]string{},
			want: true,
		},
		{
			name: "local can disable migrations",
			env: map[string]string{
				"NANDA_AUTO_MIGRATE": "false",
			},
			want: false,
		},
		{
			name: "production default disables migrations",
			env: map[string]string{
				"NANDA_MODE":               ModeProduction,
				"NANDA_PRIVATE_KEY_BASE64": testPrivateKeyBase64(t),
			},
			want: false,
		},
		{
			name: "production can explicitly enable migrations",
			env: map[string]string{
				"NANDA_MODE":               ModeProduction,
				"NANDA_PRIVATE_KEY_BASE64": testPrivateKeyBase64(t),
				"NANDA_AUTO_MIGRATE":       "true",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadLocal(func(key string) string { return tt.env[key] })
			if err != nil {
				t.Fatalf("load local: %v", err)
			}
			if cfg.AutoMigrate != tt.want {
				t.Fatalf("auto migrate = %v, want %v", cfg.AutoMigrate, tt.want)
			}
		})
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

func testPrivateKeyBase64(t *testing.T) string {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(privateKey)
}
