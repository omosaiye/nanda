package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func WithBearerAuth(next http.Handler, token string) http.Handler {
	if token == "" {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = EnsureRequestID(w, r)
		if !validBearerToken(r.Header.Get("Authorization"), token) {
			WriteJSONError(w, r, http.StatusUnauthorized, "unauthorized", http.StatusText(http.StatusUnauthorized))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validBearerToken(header string, token string) bool {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := header[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}
