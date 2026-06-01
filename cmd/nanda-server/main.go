package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/solai/nanda/internal/admin"
	"github.com/solai/nanda/internal/api"
	"github.com/solai/nanda/internal/audit"
	"github.com/solai/nanda/internal/config"
	"github.com/solai/nanda/internal/facts"
	"github.com/solai/nanda/internal/index"
	"github.com/solai/nanda/internal/registration"
	"github.com/solai/nanda/internal/resolver"
	"github.com/solai/nanda/internal/revocation"
	"github.com/solai/nanda/internal/trust"
)

func main() {
	if err := run(context.Background()); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.LoadLocalFromEnv()
	if err != nil {
		return err
	}
	if err := config.ValidateRuntime(cfg); err != nil {
		return err
	}

	db, err := sql.Open("pgx", cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	if cfg.AutoMigrate {
		if err := runMigrations(ctx, db); err != nil {
			return err
		}
	}

	handler, err := newLocalHandler(cfg, db)
	if err != nil {
		return err
	}
	if cfg.EphemeralKey {
		slog.Warn("using ephemeral local signing key; set NANDA_PRIVATE_KEY_BASE64 for stable records")
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting nanda server", "addr", cfg.Addr, "mode", cfg.Mode, "factsDir", cfg.FactsDir)
		errCh <- server.ListenAndServe()
	}()

	shutdownSignalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-shutdownSignalCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}

func newLocalHandler(cfg config.Local, db *sql.DB) (http.Handler, error) {
	indexStore, err := index.NewPostgresStore(db)
	if err != nil {
		return nil, err
	}
	factsStore, err := facts.NewFilesystemStore(cfg.FactsDir)
	if err != nil {
		return nil, err
	}
	pointerStore, err := facts.NewPostgresPointerStore(db)
	if err != nil {
		return nil, err
	}
	var auditStore audit.Store
	auditStore, err = audit.NewPostgresStore(db)
	if err != nil {
		slog.Warn("postgres audit store unavailable; falling back to memory audit store", "err", err)
		auditStore = audit.NewMemoryStore()
	}
	revocationStore, err := revocation.NewPostgresStore(db)
	if err != nil {
		return nil, err
	}
	trustVerifier, err := newLocalTrustVerifier(cfg, revocationStore)
	if err != nil {
		return nil, err
	}
	slog.Info("configured trusted capability issuers", "count", len(cfg.TrustedIssuers))

	registrationService, err := registration.NewService(
		factsStore,
		indexStore,
		cfg.PrivateKey,
		registration.WithPointerStore(pointerStore),
		registration.WithAuditStore(auditStore),
	)
	if err != nil {
		return nil, err
	}
	resolverService, err := resolver.NewService(
		indexStore,
		factsStore,
		pointerStore,
		cfg.PublicKey,
		resolver.WithTrustVerifier(trustVerifier),
		resolver.WithAuditStore(auditStore),
	)
	if err != nil {
		return nil, err
	}
	adminService, err := admin.NewService(indexStore, auditStore, revocationStore)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	registerHandler := api.RegisterAgentHandler(registrationService)
	resolveHandler := api.ResolveAgentHandler(resolverService)
	adminHandlers := adminRouteHandlers{
		getAgent:            api.AdminGetAgentHandler(adminService),
		listAudit:           api.AdminListAuditHandler(adminService),
		listAuditByAgent:    api.AdminListAuditByAgentHandler(adminService),
		getRevocationStatus: api.AdminGetRevocationStatusHandler(adminService),
		setRevocationStatus: api.AdminSetRevocationStatusHandler(adminService),
	}
	addRoutes(mux, registerHandler, resolveHandler, adminHandlers, cfg.APIToken)
	return api.WithRequestID(mux), nil
}

func newLocalTrustVerifier(cfg config.Local, revocationChecker trust.RevocationChecker) (*trust.Verifier, error) {
	return trust.NewVerifier(
		cfg.TrustedIssuers,
		trust.WithRevocationChecker(revocationChecker),
	)
}

type adminRouteHandlers struct {
	getAgent            http.Handler
	listAudit           http.Handler
	listAuditByAgent    http.Handler
	getRevocationStatus http.Handler
	setRevocationStatus http.Handler
}

func addRoutes(mux *http.ServeMux, registerHandler http.Handler, resolveHandler http.Handler, adminHandlers adminRouteHandlers, apiToken string) {
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/readyz", readyzHandler)
	mux.Handle("/v1/agents/register", api.WithBearerAuth(registerHandler, apiToken))
	mux.Handle("/v1/resolve", api.WithBearerAuth(resolveHandler, apiToken))
	mux.Handle("/v1/admin/agents/{agentId}", api.WithBearerAuth(adminHandlers.getAgent, apiToken))
	mux.Handle("/v1/admin/audit", api.WithBearerAuth(adminHandlers.listAudit, apiToken))
	mux.Handle("/v1/admin/audit/{agentId}", api.WithBearerAuth(adminHandlers.listAuditByAgent, apiToken))
	mux.Handle("/v1/admin/revocation", api.WithBearerAuth(adminHandlers.setRevocationStatus, apiToken))
	mux.Handle("/v1/admin/revocation/{issuer}/{credentialId}", api.WithBearerAuth(adminHandlers.getRevocationStatus, apiToken))
}

func runMigrations(ctx context.Context, db *sql.DB) error {
	migrationsDir, err := findMigrationsDir()
	if err != nil {
		return err
	}
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		return fmt.Errorf("find migrations: %w", err)
	}
	if len(files) == 0 {
		return errors.New("no migrations found in ./migrations")
	}
	sort.Strings(files)
	for _, file := range files {
		sqlBytes, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file, err)
		}
		if _, err := db.ExecContext(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", file, err)
		}
	}
	return nil
}

func findMigrationsDir() (string, error) {
	for _, candidate := range []string{"migrations", "../../migrations"} {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate, nil
		}
	}
	return "", errors.New("migrations directory not found")
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	writeStatus(w, "ok")
}

func readyzHandler(w http.ResponseWriter, _ *http.Request) {
	writeStatus(w, "ready")
}

type statusResponse struct {
	Status string `json:"status"`
}

func writeStatus(w http.ResponseWriter, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(statusResponse{Status: status}); err != nil {
		slog.Error("write status response failed", "err", err)
	}
}
