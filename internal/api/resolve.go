package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/solai/nanda/internal/resolver"
)

type ResolverService interface {
	Resolve(ctx context.Context, req resolver.ResolveRequest) (resolver.ResolveResponse, error)
}

func ResolveAgentHandler(service ResolverService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = EnsureRequestID(w, r)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			WriteJSONError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed))
			return
		}

		var req resolver.ResolveRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			WriteJSONError(w, r, http.StatusBadRequest, "invalid_resolve_request", "invalid resolve request")
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			WriteJSONError(w, r, http.StatusBadRequest, "invalid_resolve_request", "invalid resolve request")
			return
		}

		resp, err := service.Resolve(r.Context(), req)
		if err != nil {
			if errors.Is(err, resolver.ErrValidation) {
				WriteJSONError(w, r, http.StatusBadRequest, "resolve_validation_failed", err.Error())
				return
			}
			if errors.Is(err, resolver.ErrNotFound) {
				WriteJSONError(w, r, http.StatusNotFound, "not_found", http.StatusText(http.StatusNotFound))
				return
			}
			if errors.Is(err, resolver.ErrTrustDenied) {
				WriteJSONError(w, r, http.StatusForbidden, "trust_denied", err.Error())
				return
			}
			if errors.Is(err, resolver.ErrExpired) {
				WriteJSONError(w, r, http.StatusGone, "expired", err.Error())
				return
			}
			slog.Error("resolve failed", "err", err, "request_id", RequestID(r))
			WriteJSONError(w, r, http.StatusInternalServerError, "internal_error", http.StatusText(http.StatusInternalServerError))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("write resolve response failed", "err", err, "request_id", RequestID(r))
		}
	})
}
