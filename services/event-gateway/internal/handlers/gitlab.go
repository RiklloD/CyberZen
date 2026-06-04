package handlers

import (
	"crypto/subtle"
	"io"
	"net/http"
	"time"

	"github.com/cyberzen/event-gateway/internal/queue"
)

// GitLab uses a static shared token in the X-Gitlab-Token header — not HMAC
// — so verification is a constant-time string compare.
type GitLab struct {
	secret string
	buf    *queue.Buffer
}

func NewGitLab(secret string, buf *queue.Buffer) *GitLab {
	return &GitLab{secret: secret, buf: buf}
}

func (h *GitLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.Header.Get("X-Gitlab-Token")
	if h.secret == "" || subtle.ConstantTimeCompare([]byte(token), []byte(h.secret)) != 1 {
		http.Error(w, "token verification failed", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20))
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	event := queue.Event{
		Provider: "gitlab",
		EventID:  r.Header.Get("X-Gitlab-Event-UUID"),
		Type:     r.Header.Get("X-Gitlab-Event"),
		Headers: map[string]string{
			"X-Gitlab-Event":      r.Header.Get("X-Gitlab-Event"),
			"X-Gitlab-Event-UUID": r.Header.Get("X-Gitlab-Event-UUID"),
		},
		Body:     body,
		Received: time.Now().UTC(),
	}
	h.buf.Append(r.Context(), event)
	w.WriteHeader(http.StatusAccepted)
}
