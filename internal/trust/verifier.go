package trust

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
	"github.com/solai/nanda/internal/agentfacts"
)

var (
	ErrDenied                    = errors.New("credential trust denied")
	ErrMissingCredential         = errors.New("no credential grants required capability")
	ErrMissingCredentialID       = errors.New("credential id is empty")
	ErrUnsupportedCredentialType = errors.New("credential type is unsupported")
	ErrUntrustedIssuer           = errors.New("credential issuer is not allowlisted")
	ErrSubjectMismatch           = errors.New("credential subject does not match requested agent id")
	ErrNotYetValid               = errors.New("credential validFrom is in the future")
	ErrExpired                   = errors.New("credential validUntil is not in the future")
	ErrMissingRequiredCapability = errors.New("credential missing required capability")
	ErrInvalidSignatureEncoding  = errors.New("credential signature is not valid base64")
	ErrInvalidSignature          = errors.New("credential signature is invalid")
	ErrCredentialRevoked         = errors.New("credential is revoked")
)

type IssuerAllowlist map[string]ed25519.PublicKey

// RevocationChecker is the v0 local revocation hook for capability credentials.
// It is intentionally not a full W3C VC Status List implementation.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, issuer string, credentialID string) (bool, error)
}

type Option func(*Verifier)

type Verifier struct {
	issuers           IssuerAllowlist
	revocationChecker RevocationChecker
}

func WithRevocationChecker(checker RevocationChecker) Option {
	return func(v *Verifier) {
		v.revocationChecker = checker
	}
}

func NewVerifier(issuers IssuerAllowlist, opts ...Option) (*Verifier, error) {
	copied := make(IssuerAllowlist, len(issuers))
	for issuer, publicKey := range issuers {
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: %s", agentaddr.ErrInvalidPublicKey, issuer)
		}
		copied[issuer] = append(ed25519.PublicKey(nil), publicKey...)
	}

	verifier := &Verifier{issuers: copied}
	for _, opt := range opts {
		opt(verifier)
	}

	return verifier, nil
}

func (v *Verifier) VerifyCapability(ctx context.Context, credentials []agentfacts.CapabilityCredential, requestedAgentID string, requiredCapability string, now time.Time) error {
	var lastErr error
	for _, credential := range credentials {
		if err := v.verifyCredential(ctx, credential, requestedAgentID, requiredCapability, now); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr != nil {
		return VerificationError{Err: lastErr}
	}

	return VerificationError{Err: ErrMissingCredential}
}

func (v *Verifier) verifyCredential(ctx context.Context, credential agentfacts.CapabilityCredential, requestedAgentID string, requiredCapability string, now time.Time) error {
	if credential.Type != agentfacts.AgentCapabilityCredential {
		return ErrUnsupportedCredentialType
	}
	if strings.TrimSpace(credential.ID) == "" {
		return ErrMissingCredentialID
	}
	publicKey, ok := v.issuers[credential.Issuer]
	if !ok {
		return ErrUntrustedIssuer
	}
	normalizedRequestedAgentID, err := agentaddr.NormalizeAgentID(requestedAgentID)
	if err != nil {
		return err
	}
	normalizedSubject, err := agentaddr.NormalizeAgentID(credential.Subject)
	if err != nil {
		return err
	}
	if normalizedSubject != normalizedRequestedAgentID {
		return ErrSubjectMismatch
	}
	if credential.ValidFrom.After(now) {
		return ErrNotYetValid
	}
	if !credential.ValidUntil.After(now) {
		return ErrExpired
	}
	if requiredCapability == "" || !slices.Contains(credential.Capabilities, requiredCapability) {
		return ErrMissingRequiredCapability
	}
	signature, err := base64.StdEncoding.DecodeString(credential.Signature)
	if err != nil {
		return ErrInvalidSignatureEncoding
	}
	payload, err := signingPayloadBytes(credential)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidSignature
	}
	if v.revocationChecker != nil {
		revoked, err := v.revocationChecker.IsRevoked(ctx, credential.Issuer, credential.ID)
		if err != nil {
			return err
		}
		if revoked {
			return ErrCredentialRevoked
		}
	}

	return nil
}

type VerificationError struct {
	Err error
}

func (e VerificationError) Error() string {
	return fmt.Sprintf("%v: %v", ErrDenied, e.Err)
}

func (e VerificationError) Unwrap() error {
	return e.Err
}

func (e VerificationError) Is(target error) bool {
	return target == ErrDenied
}

type signingPayload struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	Capabilities []string  `json:"capabilities"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidUntil   time.Time `json:"validUntil"`
}

// signingPayloadBytes is the v0 deterministic JSON payload for Ed25519 verification.
// It intentionally excludes signature and is not full W3C VC canonicalization.
func signingPayloadBytes(credential agentfacts.CapabilityCredential) ([]byte, error) {
	return json.Marshal(signingPayload{
		ID:           credential.ID,
		Type:         credential.Type,
		Issuer:       credential.Issuer,
		Subject:      credential.Subject,
		Capabilities: credential.Capabilities,
		ValidFrom:    credential.ValidFrom,
		ValidUntil:   credential.ValidUntil,
	})
}
