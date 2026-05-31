package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/solai/nanda/internal/registration"
)

type RegistrationService interface {
	Register(ctx context.Context, req registration.RegisterRequest) (registration.RegisterResponse, error)
}

func RegisterAgentHandler(service RegistrationService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = EnsureRequestID(w, r)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			WriteJSONError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed))
			return
		}

		var req registration.RegisterRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			WriteJSONError(w, r, http.StatusBadRequest, "invalid_registration_request", "invalid registration request")
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			WriteJSONError(w, r, http.StatusBadRequest, "invalid_registration_request", "invalid registration request")
			return
		}

		resp, err := service.Register(r.Context(), req)
		if err != nil {
			if errors.Is(err, registration.ErrValidation) {
				WriteJSONError(w, r, http.StatusBadRequest, "registration_validation_failed", err.Error())
				return
			}
			slog.Error("registration failed", "err", err, "request_id", RequestID(r))
			WriteJSONError(w, r, http.StatusInternalServerError, "internal_error", http.StatusText(http.StatusInternalServerError))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("write registration response failed", "err", err, "request_id", RequestID(r))
		}
	})
}
