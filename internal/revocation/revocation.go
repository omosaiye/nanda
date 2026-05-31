package revocation

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

var (
	ErrNotFound     = errors.New("revocation record not found")
	ErrInvalidInput = errors.New("invalid revocation input")
)

type Record struct {
	Issuer       string
	CredentialID string
	Status       string
	Reason       string
	UpdatedAt    time.Time
}

type Store interface {
	SetStatus(ctx context.Context, issuer string, credentialID string, status string, reason string) error
	GetStatus(ctx context.Context, issuer string, credentialID string) (Record, error)
	IsRevoked(ctx context.Context, issuer string, credentialID string) (bool, error)
}

func validateKey(issuer string, credentialID string) error {
	if issuer == "" {
		return fmt.Errorf("%w: issuer is required", ErrInvalidInput)
	}
	if credentialID == "" {
		return fmt.Errorf("%w: credential id is required", ErrInvalidInput)
	}
	return nil
}

func validateStatus(status string) error {
	switch status {
	case StatusActive, StatusRevoked:
		return nil
	default:
		return fmt.Errorf("%w: unsupported status %q", ErrInvalidInput, status)
	}
}
