package handlers

import (
	"crypto/subtle"
	"io"
	"net/http"
	"time"

	"github.com/cyberzen/event-gateway/internal/queue"
)

// Jenkins notifications historically did not include signatures. Most teams
// front them with a shared token in a custom header. We treat
// X-Jenkins-Token as the contract; absent or mismatched → 401.
type Jenkins struct {
	secret string
	buf    *queue.Buffer
}

func NewJenkins(secret string, buf *queue.Buffer) *Jenkins {
	return &Jenkins{secret: secret, buf: buf}
}

func (h *Jenkins) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.Header.Get("X-Jenkins-Token")
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
		Provider: "jenkins",
		EventID:  r.Header.Get("X-Jenkins-Notification-Id"),
		Type:     r.Header.Get("X-Jenkins-Event"),
		Headers: map[string]string{
			"X-Jenkins-Event":           r.Header.Get("X-Jenkins-Event"),
			"X-Jenkins-Notification-Id": r.Header.Get("X-Jenkins-Notification-Id"),
		},
		Body:     body,
		Received: time.Now().UTC(),
	}
	h.buf.Append(r.Context(), event)
	w.WriteHeader(http.StatusAccepted)
}
