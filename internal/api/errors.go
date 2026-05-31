package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

type errorResponse struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func WriteJSONError(w http.ResponseWriter, r *http.Request, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(errorResponse{
		Error: errorBody{
			Code:    code,
			Message: message,
		},
	}); err != nil {
		slog.Error("write error response failed", "err", err, "request_id", RequestID(r))
	}
}
