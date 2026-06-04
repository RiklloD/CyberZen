package handlers

import (
	"io"
	"net/http"
	"time"

	"github.com/cyberzen/event-gateway/internal/auth"
	"github.com/cyberzen/event-gateway/internal/queue"
)

// CircleCI v2 signs webhook bodies with HMAC-SHA256 in Circleci-Signature
// (formatted as "v1=<hex>").
type CircleCI struct {
	secret string
	buf    *queue.Buffer
}

func NewCircleCI(secret string, buf *queue.Buffer) *CircleCI {
	return &CircleCI{secret: secret, buf: buf}
}

func (h *CircleCI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20))
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	sig := r.Header.Get("Circleci-Signature")
	// CircleCI prefixes the signature with "v1=" rather than "sha256=";
	// strip it so the shared helper sees a clean hex string.
	if len(sig) > 3 && sig[:3] == "v1=" {
		sig = sig[3:]
	}
	if err := auth.VerifyHMACSHA256(h.secret, body, sig); err != nil {
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}
	event := queue.Event{
		Provider: "circleci",
		EventID:  r.Header.Get("Circleci-Event-Id"),
		Type:     r.Header.Get("Circleci-Event-Type"),
		Headers: map[string]string{
			"Circleci-Event-Type": r.Header.Get("Circleci-Event-Type"),
			"Circleci-Event-Id":   r.Header.Get("Circleci-Event-Id"),
		},
		Body:     body,
		Received: time.Now().UTC(),
	}
	h.buf.Append(r.Context(), event)
	w.WriteHeader(http.StatusAccepted)
}
