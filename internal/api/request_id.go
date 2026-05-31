package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

const requestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

var fallbackRequestIDCounter uint64

func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = EnsureRequestID(w, r)
		next.ServeHTTP(w, r)
	})
}

func EnsureRequestID(w http.ResponseWriter, r *http.Request) *http.Request {
	requestID := RequestID(r)
	if requestID == "" {
		requestID = newRequestID()
	}
	w.Header().Set(requestIDHeader, requestID)
	return r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, requestID))
}

func RequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	requestID, _ := r.Context().Value(requestIDContextKey{}).(string)
	if requestID != "" {
		return requestID
	}
	return r.Header.Get(requestIDHeader)
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	count := atomic.AddUint64(&fallbackRequestIDCounter, 1)
	return fmt.Sprintf("%x-%x", time.Now().UnixNano(), count)
}
