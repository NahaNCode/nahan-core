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
	mu       sync.Mutex
	document *EgressDocument
	cancel   context.CancelFunc
	running  bool
	next     time.Time
	cursor   int
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
		return
	}
	if document.Validate() != nil || check == nil {
		return
	}
	changed := h.document == nil || *h.document != *document
	if changed && h.cancel != nil {
		h.cancel()
	}
	if h.running {
		return
	}
	if !changed && time.Now().Before(h.next) {
		return
	}
	copyDocument := *document
	h.document = &copyDocument
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	h.cancel = cancel
	h.running = true
	go func() {
		defer cancel()
		defer func() { h.mu.Lock(); h.running = false; h.next = time.Now().Add(60 * time.Second); h.mu.Unlock() }()
		results := check(ctx)
		if ctx.Err() != nil || len(results) == 0 || len(results) > 256 {
			return
		}
		_ = c.request(ctx, "POST", "egress/health", map[string]any{"revision": copyDocument.Revision, "digest": copyDocument.Digest, "results": results}, nil)
	}()
}
func (c *Client) CloseEgressHealth() { c.ObserveEgress(nil, nil) }
