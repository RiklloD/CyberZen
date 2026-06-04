package handlers

import (
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cyberzen/event-gateway/internal/queue"
)

// AzureDevOps signs service hooks with HTTP Basic auth. The secret is the
// base64("user:pass") configured on the service hook; we compare it
// constant-time against the Authorization header.
type AzureDevOps struct {
	secret string
	buf    *queue.Buffer
}

func NewAzureDevOps(secret string, buf *queue.Buffer) *AzureDevOps {
	return &AzureDevOps{secret: secret, buf: buf}
}

func (h *AzureDevOps) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.secret == "" {
		http.Error(w, "secret not configured", http.StatusUnauthorized)
		return
	}
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Basic ") {
		http.Error(w, "missing basic auth", http.StatusUnauthorized)
		return
	}
	provided, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, "Basic "))
	if err != nil {
		http.Error(w, "invalid basic auth", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare(provided, []byte(h.secret)) != 1 {
		http.Error(w, "basic auth mismatch", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20))
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	event := queue.Event{
		Provider: "azuredevops",
		EventID:  r.Header.Get("X-VSS-RequestId"),
		Type:     r.Header.Get("X-VSS-EventType"),
		Headers: map[string]string{
			"X-VSS-RequestId":   r.Header.Get("X-VSS-RequestId"),
			"X-VSS-EventType":   r.Header.Get("X-VSS-EventType"),
			"X-VSS-SubscriptionId": r.Header.Get("X-VSS-SubscriptionId"),
		},
		Body:     body,
		Received: time.Now().UTC(),
	}
	h.buf.Append(r.Context(), event)
	w.WriteHeader(http.StatusAccepted)
}
