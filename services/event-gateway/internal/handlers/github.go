// Package handlers implements per-provider webhook intake.
//
// Each handler:
//   - Reads and verifies the request signature using internal/auth.
//   - Parses the minimum set of headers needed to derive provider/event_id/type.
//   - Enqueues the raw body onto the shared queue.Buffer.
//
// Parsing the payload body is intentionally deferred: the Convex side owns
// schema interpretation so we stay decoupled from provider format churn.
package handlers

import (
	"io"
	"net/http"
	"time"

	"github.com/cyberzen/event-gateway/internal/auth"
	"github.com/cyberzen/event-gateway/internal/queue"
)

// GitHub validates GitHub-style HMAC-SHA256 signatures (X-Hub-Signature-256).
type GitHub struct {
	secret string
	buf    *queue.Buffer
}

// NewGitHub constructs a GitHub webhook handler. The secret is the value
// configured on the GitHub side; an empty secret causes all requests to
// be rejected with 401 so misconfiguration fails closed.
func NewGitHub(secret string, buf *queue.Buffer) *GitHub {
	return &GitHub{secret: secret, buf: buf}
}

func (h *GitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20))
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	sig := r.Header.Get("X-Hub-Signature-256")
	if err := auth.VerifyHMACSHA256(h.secret, body, sig); err != nil {
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}

	event := queue.Event{
		Provider: "github",
		EventID:  r.Header.Get("X-GitHub-Delivery"),
		Type:     r.Header.Get("X-GitHub-Event"),
		Headers: map[string]string{
			"X-GitHub-Delivery":     r.Header.Get("X-GitHub-Delivery"),
			"X-GitHub-Event":        r.Header.Get("X-GitHub-Event"),
			"X-GitHub-Hook-ID":      r.Header.Get("X-GitHub-Hook-ID"),
			"X-GitHub-Installation": r.Header.Get("X-GitHub-Installation-Target-ID"),
		},
		Body:     body,
		Received: time.Now().UTC(),
	}
	h.buf.Append(r.Context(), event)

	w.WriteHeader(http.StatusAccepted)
}
