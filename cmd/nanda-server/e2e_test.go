package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/solai/nanda/internal/config"
	"github.com/solai/nanda/internal/registration"
	"github.com/solai/nanda/internal/resolver"
)

func TestLocalServerRegisterResolveEndToEnd(t *testing.T) {
	dsn := os.Getenv("NANDA_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set NANDA_POSTGRES_DSN to run PostgreSQL integration tests")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	if err := runLocalMigrations(ctx, db); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	cleanLocalTables(t, db)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cfg, err := config.LoadLocal(func(key string) string {
		switch key {
		case "NANDA_POSTGRES_DSN":
			return dsn
		case "NANDA_FACTS_DIR":
			return t.TempDir()
		case "NANDA_PRIVATE_KEY_BASE64":
			return base64.StdEncoding.EncodeToString(privateKey)
		case "NANDA_PUBLIC_KEY_BASE64":
			return base64.StdEncoding.EncodeToString(publicKey)
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	handler, err := newLocalHandler(cfg, db)
	if err != nil {
		t.Fatalf("new local handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	registerResp := postJSON[registration.RegisterResponse](t, server.URL+"/v1/agents/register", `{
		"agentId": "agent.example",
		"ttlSeconds": 300,
		"sequence": 1,
		"facts": {
			"schemaVersion": "nanda.agentfacts.v0",
			"id": "agent.example",
			"controller": "did:example:controller",
			"validFrom": "2026-01-01T00:00:00Z",
			"validUntil": "2030-01-01T00:00:00Z",
			"capabilities": ["chat"],
			"endpoints": [
				{
					"id": "primary",
					"type": "static",
					"url": "https://agent.example/api",
					"protocol": "https",
					"ttlSeconds": 60
				}
			]
		}
	}`)
	if registerResp.FactsPtrHash128 == "" {
		t.Fatal("registration response missing facts pointer hash")
	}
	if registerResp.AgentAddrRecordBase64 == "" {
		t.Fatal("registration response missing signed agent address record")
	}

	resolveResp := postJSON[resolver.ResolveResponse](t, server.URL+"/v1/resolve", `{
		"agentId": "agent.example"
	}`)
	if resolveResp.Endpoint.URL != "https://agent.example/api" {
		t.Fatalf("endpoint url = %q, want https://agent.example/api", resolveResp.Endpoint.URL)
	}
	if !resolveResp.ProofBundle.AgentAddrSignatureVerified {
		t.Fatal("proof bundle missing signature verification")
	}
	if !resolveResp.ProofBundle.AgentFactsPointerHashVerified {
		t.Fatal("proof bundle missing facts pointer hash verification")
	}
	if !resolveResp.ProofBundle.AgentFactsSchemaVerified {
		t.Fatal("proof bundle missing schema verification")
	}

	var auditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE agent_id = $1`, "agent.example").Scan(&auditCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if auditCount < 2 {
		t.Fatalf("audit event count = %d, want at least 2", auditCount)
	}
}

func postJSON[T any](t *testing.T, url string, body string) T {
	t.Helper()

	resp, err := http.Post(url, "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var errorBody bytes.Buffer
		_, _ = errorBody.ReadFrom(resp.Body)
		t.Fatalf("post %s status = %d; body=%q", url, resp.StatusCode, errorBody.String())
	}

	var decoded T
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response from %s: %v", url, err)
	}
	return decoded
}

func cleanLocalTables(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.ExecContext(context.Background(), `
		TRUNCATE
			facts_pointers,
			audit_events,
			credential_revocations,
			agent_addr_history,
			agent_addr_records
		RESTART IDENTITY
	`)
	if err != nil {
		t.Fatalf("clean local tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `
			TRUNCATE
				facts_pointers,
				audit_events,
				credential_revocations,
				agent_addr_history,
				agent_addr_records
			RESTART IDENTITY
		`)
	})
}
