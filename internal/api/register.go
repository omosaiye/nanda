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
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		var req registration.RegisterRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "invalid registration request", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			http.Error(w, "invalid registration request", http.StatusBadRequest)
			return
		}

		resp, err := service.Register(r.Context(), req)
		if err != nil {
			if errors.Is(err, registration.ErrValidation) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			slog.Error("registration failed", "err", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("write registration response failed", "err", err)
		}
	})
}
