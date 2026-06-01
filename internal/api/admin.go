package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/solai/nanda/internal/admin"
	"github.com/solai/nanda/internal/audit"
)

type AdminService interface {
	GetAgent(ctx context.Context, agentID string) (admin.AgentResponse, error)
	ListAudit(ctx context.Context, query audit.Query) (audit.ListResult, error)
	ListAuditByAgent(ctx context.Context, agentID string, query audit.Query) (audit.ListResult, error)
	GetRevocationStatus(ctx context.Context, issuer string, credentialID string) (admin.RevocationStatusResponse, error)
	SetRevocationStatus(ctx context.Context, req admin.SetRevocationStatusRequest) (admin.SetRevocationStatusResponse, error)
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

		query, err := parseAuditQuery(r)
		if err != nil {
			writeAdminError(w, r, err)
			return
		}
		result, err := service.ListAudit(r.Context(), query)
		if err != nil {
			writeAdminError(w, r, err)
			return
		}
		writeJSON(w, r, result)
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

		query, err := parseAuditQuery(r)
		if err != nil {
			writeAdminError(w, r, err)
			return
		}
		result, err := service.ListAuditByAgent(r.Context(), r.PathValue("agentId"), query)
		if err != nil {
			writeAdminError(w, r, err)
			return
		}
		writeJSON(w, r, result)
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

func AdminSetRevocationStatusHandler(service AdminService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = EnsureRequestID(w, r)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			WriteJSONError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed))
			return
		}

		var req admin.SetRevocationStatusRequest
		if err := decodeJSONBody(r, &req); err != nil {
			WriteJSONError(w, r, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		resp, err := service.SetRevocationStatus(r.Context(), req)
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

func decodeJSONBody(r *http.Request, value any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func parseAuditQuery(r *http.Request) (audit.Query, error) {
	values := r.URL.Query()
	query := audit.Query{
		EventType: values.Get("eventType"),
		Decision:  values.Get("decision"),
	}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			return audit.Query{}, admin.ValidationError{Field: "limit", Err: errors.New("limit must be a positive integer")}
		}
		query.Limit = limit
	}
	if raw := values.Get("offset"); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return audit.Query{}, admin.ValidationError{Field: "offset", Err: errors.New("offset must be a non-negative integer")}
		}
		query.Offset = offset
	}
	if _, err := audit.NormalizeQuery(query); err != nil {
		return audit.Query{}, admin.ValidationError{Err: err}
	}
	return query, nil
}

func writeJSON(w http.ResponseWriter, r *http.Request, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("write json response failed", "err", err, "request_id", RequestID(r))
	}
}
