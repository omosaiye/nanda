package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

const (
	defaultAddr     = ":8080"
	defaultFactsDir = "./var/facts"

	ModeLocal      = "local"
	ModeProduction = "production"
)

var (
	ErrInvalidKeyConfig = errors.New("invalid key configuration")
	ErrInvalidMode      = errors.New("invalid runtime mode")
)

type Local struct {
	Addr         string
	Mode         string
	PostgresDSN  string
	FactsDir     string
	APIToken     string
	AutoMigrate  bool
	PrivateKey   ed25519.PrivateKey
	PublicKey    ed25519.PublicKey
	EphemeralKey bool
}

func LoadLocalFromEnv() (Local, error) {
	return LoadLocal(getenv)
}

func LoadLocal(lookup func(string) string) (Local, error) {
	mode := valueOrDefault(lookup("NANDA_MODE"), ModeLocal)
	if mode != ModeLocal && mode != ModeProduction {
		return Local{}, fmt.Errorf("%w: NANDA_MODE must be local or production", ErrInvalidMode)
	}

	privateKeyEncoded := lookup("NANDA_PRIVATE_KEY_BASE64")
	if mode == ModeProduction && privateKeyEncoded == "" {
		return Local{}, errors.New("NANDA_PRIVATE_KEY_BASE64 is required in production mode")
	}

	cfg := Local{
		Addr:        valueOrDefault(lookup("NANDA_ADDR"), defaultAddr),
		Mode:        mode,
		PostgresDSN: lookup("NANDA_POSTGRES_DSN"),
		FactsDir:    valueOrDefault(lookup("NANDA_FACTS_DIR"), defaultFactsDir),
		APIToken:    lookup("NANDA_API_TOKEN"),
		AutoMigrate: shouldAutoMigrate(mode, lookup("NANDA_AUTO_MIGRATE")),
	}

	privateKey, generated, err := loadPrivateKey(privateKeyEncoded)
	if err != nil {
		return Local{}, err
	}
	cfg.PrivateKey = privateKey
	cfg.EphemeralKey = generated

	publicKey, err := loadPublicKey(lookup("NANDA_PUBLIC_KEY_BASE64"), privateKey)
	if err != nil {
		return Local{}, err
	}
	cfg.PublicKey = publicKey

	return cfg, nil
}

func ValidateRuntime(cfg Local) error {
	if cfg.Mode != ModeLocal && cfg.Mode != ModeProduction {
		return fmt.Errorf("%w: NANDA_MODE must be local or production", ErrInvalidMode)
	}
	if cfg.PostgresDSN == "" {
		return errors.New("NANDA_POSTGRES_DSN is required")
	}
	if cfg.Mode == ModeProduction {
		if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
			return errors.New("NANDA_PRIVATE_KEY_BASE64 is required in production mode")
		}
		if cfg.EphemeralKey {
			return errors.New("ephemeral signing keys are forbidden in production mode")
		}
		if cfg.APIToken == "" {
			return errors.New("NANDA_API_TOKEN is required in production mode")
		}
	}
	return nil
}

func loadPrivateKey(encoded string) (ed25519.PrivateKey, bool, error) {
	if encoded == "" {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("generate ephemeral local private key: %w", err)
		}
		return privateKey, true, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false, fmt.Errorf("%w: decode NANDA_PRIVATE_KEY_BASE64: %v", ErrInvalidKeyConfig, err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("%w: NANDA_PRIVATE_KEY_BASE64 decoded length = %d, want %d", ErrInvalidKeyConfig, len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), false, nil
}

func loadPublicKey(encoded string, privateKey ed25519.PrivateKey) (ed25519.PublicKey, error) {
	derived, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: derive ed25519 public key", ErrInvalidKeyConfig)
	}
	if encoded == "" {
		return append(ed25519.PublicKey(nil), derived...), nil
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: decode NANDA_PUBLIC_KEY_BASE64: %v", ErrInvalidKeyConfig, err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: NANDA_PUBLIC_KEY_BASE64 decoded length = %d, want %d", ErrInvalidKeyConfig, len(decoded), ed25519.PublicKeySize)
	}
	if !bytes.Equal(decoded, derived) {
		return nil, fmt.Errorf("%w: NANDA_PUBLIC_KEY_BASE64 does not match NANDA_PRIVATE_KEY_BASE64", ErrInvalidKeyConfig)
	}
	return ed25519.PublicKey(decoded), nil
}

func valueOrDefault(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func shouldAutoMigrate(mode string, value string) bool {
	if mode == ModeLocal {
		return value != "false"
	}
	return value == "true"
}

func getenv(key string) string {
	return os.Getenv(key)
}
