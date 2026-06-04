package handlers

import (
	"io"
	"net/http"
	"time"

	"github.com/cyberzen/event-gateway/internal/auth"
	"github.com/cyberzen/event-gateway/internal/queue"
)

// Bitbucket Cloud signs payloads with HMAC-SHA256 in X-Hub-Signature.
type Bitbucket struct {
	secret string
	buf    *queue.Buffer
}

func NewBitbucket(secret string, buf *queue.Buffer) *Bitbucket {
	return &Bitbucket{secret: secret, buf: buf}
}

func (h *Bitbucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20))
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	sig := r.Header.Get("X-Hub-Signature")
	if err := auth.VerifyHMACSHA256(h.secret, body, sig); err != nil {
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}
	event := queue.Event{
		Provider: "bitbucket",
		EventID:  r.Header.Get("X-Request-UUID"),
		Type:     r.Header.Get("X-Event-Key"),
		Headers: map[string]string{
			"X-Event-Key":    r.Header.Get("X-Event-Key"),
			"X-Request-UUID": r.Header.Get("X-Request-UUID"),
			"X-Hook-UUID":    r.Header.Get("X-Hook-UUID"),
		},
		Body:     body,
		Received: time.Now().UTC(),
	}
	h.buf.Append(r.Context(), event)
	w.WriteHeader(http.StatusAccepted)
}
