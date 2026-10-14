package controlplane

import (
	"context"
	"sync"
	"time"
)

type preflightAttempt struct {
	document EgressDocument
	cancel   context.CancelFunc
	done     chan struct{}
	code     string
	finished time.Time
}

type egressPreflight struct {
	mu      sync.Mutex
	attempt *preflightAttempt
}

// One bounded worker probes a candidate while the polling loop renews live
// routes. Results are scoped to the exact immutable document, never its draft.
func (c *Client) PreparedReceipt(ctx context.Context, document *EgressDocument, check func(context.Context) error) error {
	p := &c.preflight
	p.mu.Lock()
	a := p.attempt
	if a != nil {
		complete := false
		select {
		case <-a.done:
			complete = true
		default:
		}
		if document == nil || a.document != *document {
			a.cancel()
			if !complete {
				p.mu.Unlock()
				return nil
			}
			p.attempt = nil
		} else if complete && time.Since(a.finished) < 30*time.Second {
			code := a.code
			p.mu.Unlock()
			return c.EgressReceipt(ctx, "prepared", *document, code)
		} else if !complete {
			p.mu.Unlock()
			return nil
		} else {
			p.attempt = nil
		}
	}
	if document == nil {
		p.mu.Unlock()
		return nil
	}
	if err := document.Validate(); err != nil {
		p.mu.Unlock()
		return err
	}
	worker, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	a = &preflightAttempt{document: *document, cancel: cancel, done: make(chan struct{})}
	p.attempt = a
	p.mu.Unlock()
	go func() {
		defer cancel()
		code := ""
		if check == nil || check(worker) != nil || worker.Err() != nil {
			code = "preflight_failed"
		}
		p.mu.Lock()
		a.code, a.finished = code, time.Now()
		close(a.done)
		p.mu.Unlock()
	}()
	return nil
}

func (c *Client) CloseEgressPreflight() {
	p := &c.preflight
	p.mu.Lock()
	a := p.attempt
	if a != nil {
		a.cancel()
	}
	p.mu.Unlock()
	if a != nil {
		<-a.done
	}
	p.mu.Lock()
	if p.attempt == a {
		p.attempt = nil
	}
	p.mu.Unlock()
}
