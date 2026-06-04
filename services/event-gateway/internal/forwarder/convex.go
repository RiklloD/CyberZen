// Package forwarder ships buffered events to the Convex HTTP endpoint.
package forwarder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cyberzen/event-gateway/internal/queue"
)

// Convex posts batched events to /eventGateway/ingest on the Convex deployment.
type Convex struct {
	URL    string
	Token  string
	client *http.Client
}

// NewConvex constructs a forwarder. URL should be the deployment HTTP URL
// (e.g. https://acme.convex.site). Token authenticates the gateway to the
// Convex action; the receiving function is responsible for verifying it.
func NewConvex(url, token string) *Convex {
	return &Convex{
		URL:   url,
		Token: token,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Send posts the batch as a single JSON request. The Convex side is expected
// to perform per-event idempotency keyed on (provider, event_id).
func (c *Convex) Send(ctx context.Context, batch []queue.Event) error {
	if c.URL == "" {
		// Allow no-op forwarding for local development.
		return nil
	}
	if len(batch) == 0 {
		return nil
	}

	payload, err := json.Marshal(map[string]any{
		"batch": batch,
	})
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}

	endpoint := c.URL + "/eventGateway/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("post batch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("convex transient error: %s", resp.Status)
	}
	if resp.StatusCode >= 400 {
		// 4xx is non-retryable: caller will log and drop.
		return errors.New("convex rejected batch: " + resp.Status)
	}
	return nil
}
