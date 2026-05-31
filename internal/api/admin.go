package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/solai/nanda/internal/admin"
	"github.com/solai/nanda/internal/audit"
)

type AdminService interface {
	GetAgent(ctx context.Context, agentID string) (admin.AgentResponse, error)
	ListAudit(ctx context.Context) ([]audit.Event, error)
	ListAuditByAgent(ctx context.Context, agentID string) ([]audit.Event, error)
	GetRevocationStatus(ctx context.Context, issuer string, credentialID string) (admin.RevocationStatusResponse, error)
}

func AdminGetAgentHandler(service AdminService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = EnsureRequestID(w, r)
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			WriteJSONError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed))
			return
		}

		resp, err := service.GetAgent(r.Context(), r.PathValue("agentId"))
		if err != nil {
			writeAdminError(w, r, err)
			return
		}
		writeJSON(w, r, resp)
	})
}

func AdminListAuditHandler(service AdminService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = EnsureRequestID(w, r)
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			WriteJSONError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed))
			return
		}

		events, err := service.ListAudit(r.Context())
		if err != nil {
			writeAdminError(w, r, err)
			return
		}
		writeJSON(w, r, events)
	})
}

func AdminListAuditByAgentHandler(service AdminService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = EnsureRequestID(w, r)
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			WriteJSONError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed))
			return
		}

		events, err := service.ListAuditByAgent(r.Context(), r.PathValue("agentId"))
		if err != nil {
			writeAdminError(w, r, err)
			return
		}
		writeJSON(w, r, events)
	})
}

func AdminGetRevocationStatusHandler(service AdminService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = EnsureRequestID(w, r)
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			WriteJSONError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed))
			return
		}

		resp, err := service.GetRevocationStatus(r.Context(), r.PathValue("issuer"), r.PathValue("credentialId"))
		if err != nil {
			writeAdminError(w, r, err)
			return
		}
		writeJSON(w, r, resp)
	})
}

func writeAdminError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, admin.ErrValidation) {
		WriteJSONError(w, r, http.StatusBadRequest, "admin_validation_failed", err.Error())
		return
	}
	if errors.Is(err, admin.ErrNotFound) {
		WriteJSONError(w, r, http.StatusNotFound, "not_found", http.StatusText(http.StatusNotFound))
		return
	}
	slog.Error("admin request failed", "err", err, "request_id", RequestID(r))
	WriteJSONError(w, r, http.StatusInternalServerError, "internal_error", http.StatusText(http.StatusInternalServerError))
}

func writeJSON(w http.ResponseWriter, r *http.Request, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("write json response failed", "err", err, "request_id", RequestID(r))
	}
}
