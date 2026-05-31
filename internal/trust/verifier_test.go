package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/solai/nanda/internal/agentfacts"
)

func TestVerifierVerifyCapabilitySuccess(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	credential := testCredential()
	signCredential(t, &credential, privateKey)
	verifier := testVerifier(t, publicKey)

	if err := verifier.VerifyCapability([]agentfacts.CapabilityCredential{credential}, " Agent.Example ", "chat", testNow()); err != nil {
		t.Fatalf("verify capability: %v", err)
	}
}

func TestVerifierRejectsBadSignature(t *testing.T) {
	publicKey, _ := testKeyPair(t)
	_, privateKey := testKeyPair(t)
	credential := testCredential()
	signCredential(t, &credential, privateKey)
	verifier := testVerifier(t, publicKey)

	err := verifier.VerifyCapability([]agentfacts.CapabilityCredential{credential}, "agent.example", "chat", testNow())
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verify error = %v, want %v", err, ErrInvalidSignature)
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("verify error = %v, want %v", err, ErrDenied)
	}
}

func TestVerifierDenialReasons(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)

	tests := []struct {
		name               string
		credentials        func() []agentfacts.CapabilityCredential
		requestedAgentID   string
		requiredCapability string
		want               error
	}{
		{
			name: "untrusted issuer",
			credentials: func() []agentfacts.CapabilityCredential {
				credential := testCredential()
				credential.Issuer = "did:example:untrusted"
				signCredential(t, &credential, privateKey)
				return []agentfacts.CapabilityCredential{credential}
			},
			requestedAgentID:   "agent.example",
			requiredCapability: "chat",
			want:               ErrUntrustedIssuer,
		},
		{
			name: "subject mismatch",
			credentials: func() []agentfacts.CapabilityCredential {
				credential := testCredential()
				credential.Subject = "other.example"
				signCredential(t, &credential, privateKey)
				return []agentfacts.CapabilityCredential{credential}
			},
			requestedAgentID:   "agent.example",
			requiredCapability: "chat",
			want:               ErrSubjectMismatch,
		},
		{
			name: "expired credential",
			credentials: func() []agentfacts.CapabilityCredential {
				credential := testCredential()
				credential.ValidUntil = testNow()
				signCredential(t, &credential, privateKey)
				return []agentfacts.CapabilityCredential{credential}
			},
			requestedAgentID:   "agent.example",
			requiredCapability: "chat",
			want:               ErrExpired,
		},
		{
			name: "not yet valid credential",
			credentials: func() []agentfacts.CapabilityCredential {
				credential := testCredential()
				credential.ValidFrom = testNow().Add(time.Minute)
				signCredential(t, &credential, privateKey)
				return []agentfacts.CapabilityCredential{credential}
			},
			requestedAgentID:   "agent.example",
			requiredCapability: "chat",
			want:               ErrNotYetValid,
		},
		{
			name: "missing required capability",
			credentials: func() []agentfacts.CapabilityCredential {
				credential := testCredential()
				signCredential(t, &credential, privateKey)
				return []agentfacts.CapabilityCredential{credential}
			},
			requestedAgentID:   "agent.example",
			requiredCapability: "write",
			want:               ErrMissingRequiredCapability,
		},
		{
			name: "unsupported credential type",
			credentials: func() []agentfacts.CapabilityCredential {
				credential := testCredential()
				credential.Type = "UnsupportedCredential"
				signCredential(t, &credential, privateKey)
				return []agentfacts.CapabilityCredential{credential}
			},
			requestedAgentID:   "agent.example",
			requiredCapability: "chat",
			want:               ErrUnsupportedCredentialType,
		},
		{
			name: "invalid base64 signature",
			credentials: func() []agentfacts.CapabilityCredential {
				credential := testCredential()
				credential.Signature = "not base64!"
				return []agentfacts.CapabilityCredential{credential}
			},
			requestedAgentID:   "agent.example",
			requiredCapability: "chat",
			want:               ErrInvalidSignatureEncoding,
		},
		{
			name: "no matching credential",
			credentials: func() []agentfacts.CapabilityCredential {
				return nil
			},
			requestedAgentID:   "agent.example",
			requiredCapability: "chat",
			want:               ErrMissingCredential,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := testVerifier(t, publicKey)

			err := verifier.VerifyCapability(tt.credentials(), tt.requestedAgentID, tt.requiredCapability, testNow())
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("verify error = %v, want %v", err, ErrDenied)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("verify error = %v, want %v", err, tt.want)
			}
		})
	}
}

func testVerifier(t *testing.T, publicKey ed25519.PublicKey) *Verifier {
	t.Helper()

	verifier, err := NewVerifier(IssuerAllowlist{"did:example:issuer": publicKey})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return verifier
}

func testCredential() agentfacts.CapabilityCredential {
	return agentfacts.CapabilityCredential{
		ID:           "credential-1",
		Type:         agentfacts.AgentCapabilityCredential,
		Issuer:       "did:example:issuer",
		Subject:      "agent.example",
		Capabilities: []string{"chat", "status"},
		ValidFrom:    testNow().Add(-time.Minute),
		ValidUntil:   testNow().Add(time.Hour),
	}
}

func signCredential(t *testing.T, credential *agentfacts.CapabilityCredential, privateKey ed25519.PrivateKey) {
	t.Helper()

	payload, err := signingPayloadBytes(*credential)
	if err != nil {
		t.Fatalf("credential signing payload: %v", err)
	}
	credential.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
}

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return publicKey, privateKey
}

func testNow() time.Time {
	return time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
}
