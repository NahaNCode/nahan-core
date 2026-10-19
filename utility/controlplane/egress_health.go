package controlplane

import (
	"context"
	"sync"
	"time"
)

type EgressHealthResult struct {
	ProfileID string    `json:"profileId"`
	Alive     bool      `json:"alive"`
	LatencyMS int64     `json:"latencyMs"`
	CheckedAt time.Time `json:"checkedAt"`
}
type egressHealth struct {
	mu         sync.Mutex
	document   *EgressDocument
	cancel     context.CancelFunc
	running    bool
	cursor     int
	wake       chan struct{}
	check      func(context.Context) []EgressHealthResult
	generation uint64
	interval   time.Duration
}

// Rotate bounded batches rather than probing an unbounded fleet on every poll.
func (c *Client) EgressHealthBatch(total, limit int) []int {
	h := &c.health
	h.mu.Lock()
	defer h.mu.Unlock()
	if total < 1 || limit < 1 {
		return nil
	}
	if limit > total {
		limit = total
	}
	indices := make([]int, limit)
	for i := range indices {
		indices[i] = (h.cursor + i) % total
	}
	h.cursor = (h.cursor + limit) % total
	return indices
}

// One worker per core. Observations never participate in route publication or leases.
func (c *Client) ObserveEgress(document *EgressDocument, check func(context.Context) []EgressHealthResult) {
	h := &c.health
	h.mu.Lock()
	defer h.mu.Unlock()
	if document == nil {
		if h.cancel != nil {
			h.cancel()
		}
		h.document = nil
		h.generation++
		h.running = false
		return
	}
	if document.Validate() != nil || check == nil {
		return
	}
	changed := h.document == nil || *h.document != *document
	copyDocument := *document
	h.document = &copyDocument
	h.check = check
	if h.running {
		if changed {
			select {
			case h.wake <- struct{}{}:
			default:
			}
		}
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.running = true
	h.generation++
	generation := h.generation
	h.wake = make(chan struct{}, 1)
	wake := h.wake
	interval := h.interval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	go func() {
		defer cancel()
		for ctx.Err() == nil {
			h.mu.Lock()
			if h.generation != generation || h.document == nil {
				h.mu.Unlock()
				return
			}
			current, probe := *h.document, h.check
			h.mu.Unlock()
			attempt, stop := context.WithTimeout(ctx, 90*time.Second)
			results := probe(attempt)
			h.mu.Lock()
			currentStillPublished := h.generation == generation && h.document != nil && *h.document == current
			h.mu.Unlock()
			if currentStillPublished && attempt.Err() == nil && len(results) > 0 && len(results) <= 256 {
				_ = c.request(attempt, "POST", "egress/health", map[string]any{"revision": current.Revision, "digest": current.Digest, "results": results}, nil)
			}
			stop()
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-wake:
				timer.Stop()
			case <-timer.C:
			}
		}
	}()
}
func (c *Client) CloseEgressHealth() { c.ObserveEgress(nil, nil) }
