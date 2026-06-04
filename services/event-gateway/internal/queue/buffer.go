// Package queue implements an in-memory event buffer with periodic flushing.
//
// The buffer is intentionally simple: events are appended to a slice under
// a mutex; a background goroutine flushes them at FlushInterval and on
// capacity overflow. Persistence is out of scope — the gateway is allowed
// to drop in-flight events on crash because every upstream provider will
// redeliver.
package queue

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Event is the envelope queued by webhook handlers and consumed by the
// forwarder. Body is the raw provider payload so the destination can
// preserve fidelity.
type Event struct {
	Provider string            `json:"provider"`
	EventID  string            `json:"event_id"`
	Type     string            `json:"type"`
	Headers  map[string]string `json:"headers"`
	Body     []byte            `json:"body"`
	Received time.Time         `json:"received"`
}

// FlushFunc is invoked with a batch of events. It must be safe to call
// concurrently with Append, but flushes themselves are serialized.
type FlushFunc func(ctx context.Context, batch []Event) error

// Buffer is a bounded, time-flushed queue.
type Buffer struct {
	capacity int
	interval time.Duration
	flush    FlushFunc

	mu     sync.Mutex
	events []Event

	wg     sync.WaitGroup
	stopCh chan struct{}
}

// NewBuffer constructs a Buffer with the given capacity and flush interval.
func NewBuffer(capacity int, interval time.Duration, flush FlushFunc) *Buffer {
	if capacity <= 0 {
		capacity = 256
	}
	if interval <= 0 {
		interval = time.Second
	}
	return &Buffer{
		capacity: capacity,
		interval: interval,
		flush:    flush,
		events:   make([]Event, 0, capacity),
		stopCh:   make(chan struct{}),
	}
}

// Append adds an event to the buffer. If the buffer exceeds capacity the
// caller's goroutine triggers an immediate flush so back-pressure stays
// local.
func (b *Buffer) Append(ctx context.Context, e Event) {
	b.mu.Lock()
	b.events = append(b.events, e)
	overflow := len(b.events) >= b.capacity
	b.mu.Unlock()

	if overflow {
		b.flushOnce(ctx)
	}
}

// Start begins the periodic flusher. It returns immediately; the flusher
// runs until ctx is canceled or Stop is called.
func (b *Buffer) Start(ctx context.Context) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		ticker := time.NewTicker(b.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-b.stopCh:
				return
			case <-ticker.C:
				b.flushOnce(ctx)
			}
		}
	}()
}

// Stop signals the periodic flusher to exit and performs a final flush so
// shutdown does not drop in-memory events. It blocks until the goroutine
// has returned or ctx is canceled.
func (b *Buffer) Stop(ctx context.Context) {
	close(b.stopCh)
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	b.flushOnce(ctx)
}

// Len returns the current buffered event count (primarily for tests).
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

func (b *Buffer) flushOnce(ctx context.Context) {
	b.mu.Lock()
	if len(b.events) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.events
	b.events = make([]Event, 0, b.capacity)
	b.mu.Unlock()

	if err := b.flush(ctx, batch); err != nil {
		slog.Error("event-gateway flush failed", "count", len(batch), "err", err)
		// Re-buffer the events at the front so a retry picks them up. We
		// bound the regrowth so a persistently failing destination cannot
		// blow up memory.
		b.mu.Lock()
		if len(b.events)+len(batch) <= b.capacity*4 {
			b.events = append(batch, b.events...)
		}
		b.mu.Unlock()
	}
}
