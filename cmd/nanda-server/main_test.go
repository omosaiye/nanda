package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/solai/nanda/internal/agentfacts"
	"github.com/solai/nanda/internal/config"
	"github.com/solai/nanda/internal/trust"
)

func TestProbeHandlers(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus string
	}{
		{
			name:       "healthz",
			handler:    healthzHandler,
			wantStatus: "ok",
		},
		{
			name:       "readyz",
			handler:    readyzHandler,
			wantStatus: "ready",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/"+tt.name, nil)
			response := httptest.NewRecorder()

			tt.handler(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status code = %d, want %d", response.Code, http.StatusOK)
			}
			if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
				t.Fatalf("content type = %q, want %q", contentType, "application/json")
			}

			var compactBody bytes.Buffer
			if err := json.Compact(&compactBody, response.Body.Bytes()); err != nil {
				t.Fatalf("compact response JSON: %v", err)
			}
			wantBody := `{"status":"` + tt.wantStatus + `"}`
			if compactBody.String() != wantBody {
				t.Fatalf("response body = %q, want %q", compactBody.String(), wantBody)
			}
		})
	}
}

func TestPublicProbesBypassAPIAuth(t *testing.T) {
	mux := http.NewServeMux()
	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	addRoutes(mux, protected, protected, testAdminHandlers(protected), "secret")

	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()

			mux.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status code = %d, want %d", response.Code, http.StatusOK)
			}
		})
	}
}

func TestProtectedRoutesRequireAPIAuthWhenConfigured(t *testing.T) {
	mux := http.NewServeMux()
	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	addRoutes(mux, protected, protected, testAdminHandlers(protected), "secret")

	for _, path := range []string{"/v1/agents/register", "/v1/resolve"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, path, nil)
			response := httptest.NewRecorder()

			mux.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status code = %d, want %d", response.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestAdminRoutesRequireAPIAuthWhenConfigured(t *testing.T) {
	mux := http.NewServeMux()
	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	addRoutes(mux, protected, protected, testAdminHandlers(protected), "secret")

	for _, path := range []string{
		"/v1/admin/agents/agent.example",
		"/v1/admin/audit",
		"/v1/admin/audit/agent.example",
		"/v1/admin/revocation",
		"/v1/admin/revocation/issuer.example/credential-1",
	} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()

			mux.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status code = %d, want %d", response.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestAdminRevocationMutationRequiresAPIAuthWhenConfigured(t *testing.T) {
	mux := http.NewServeMux()
	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	addRoutes(mux, protected, protected, testAdminHandlers(protected), "secret")

	request := httptest.NewRequest(http.MethodPost, "/v1/admin/revocation", nil)
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestAdminRevocationMutationAllowsValidAPIAuthWhenConfigured(t *testing.T) {
	mux := http.NewServeMux()
	reached := false
	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	addRoutes(mux, protected, protected, testAdminHandlers(protected), "secret")

	request := httptest.NewRequest(http.MethodPost, "/v1/admin/revocation", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusOK)
	}
	if !reached {
		t.Fatal("handler was not reached")
	}
}

func TestAdminRoutesAllowValidAPIAuthWhenConfigured(t *testing.T) {
	mux := http.NewServeMux()
	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	addRoutes(mux, protected, protected, testAdminHandlers(protected), "secret")

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/audit", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestNewLocalTrustVerifierUsesConfiguredIssuers(t *testing.T) {
	publicKey, privateKey := testIssuerKeyPair(t)
	cfg := config.Local{
		TrustedIssuers: trust.IssuerAllowlist{
			"did:example:issuer": publicKey,
		},
	}
	verifier, err := newLocalTrustVerifier(cfg, nil)
	if err != nil {
		t.Fatalf("new local trust verifier: %v", err)
	}
	credential := testCapabilityCredential()
	signCapabilityCredential(t, &credential, privateKey)

	err = verifier.VerifyCapability(context.Background(), []agentfacts.CapabilityCredential{credential}, "agent.example", "chat", testNow())
	if err != nil {
		t.Fatalf("verify capability: %v", err)
	}
}

func TestNewLocalTrustVerifierFailsClosedWithoutConfiguredIssuer(t *testing.T) {
	_, privateKey := testIssuerKeyPair(t)
	verifier, err := newLocalTrustVerifier(config.Local{}, nil)
	if err != nil {
		t.Fatalf("new local trust verifier: %v", err)
	}
	credential := testCapabilityCredential()
	signCapabilityCredential(t, &credential, privateKey)

	err = verifier.VerifyCapability(context.Background(), []agentfacts.CapabilityCredential{credential}, "agent.example", "chat", testNow())
	if !errors.Is(err, trust.ErrUntrustedIssuer) {
		t.Fatalf("verify capability error = %v, want %v", err, trust.ErrUntrustedIssuer)
	}
}

func testAdminHandlers(handler http.Handler) adminRouteHandlers {
	return adminRouteHandlers{
		getAgent:            handler,
		listAudit:           handler,
		listAuditByAgent:    handler,
		getRevocationStatus: handler,
		setRevocationStatus: handler,
	}
}

func testCapabilityCredential() agentfacts.CapabilityCredential {
	return agentfacts.CapabilityCredential{
		ID:           "credential-1",
		Type:         agentfacts.AgentCapabilityCredential,
		Issuer:       "did:example:issuer",
		Subject:      "agent.example",
		Capabilities: []string{"chat"},
		ValidFrom:    testNow().Add(-time.Minute),
		ValidUntil:   testNow().Add(time.Hour),
	}
}

func signCapabilityCredential(t *testing.T, credential *agentfacts.CapabilityCredential, privateKey ed25519.PrivateKey) {
	t.Helper()

	payload, err := json.Marshal(credentialSigningPayload{
		ID:           credential.ID,
		Type:         credential.Type,
		Issuer:       credential.Issuer,
		Subject:      credential.Subject,
		Capabilities: credential.Capabilities,
		ValidFrom:    credential.ValidFrom,
		ValidUntil:   credential.ValidUntil,
	})
	if err != nil {
		t.Fatalf("marshal credential signing payload: %v", err)
	}
	credential.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
}

type credentialSigningPayload struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	Capabilities []string  `json:"capabilities"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidUntil   time.Time `json:"validUntil"`
}

func testIssuerKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
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
