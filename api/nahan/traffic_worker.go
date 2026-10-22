package nahan

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/NahaNCode/nahan-core/utility/outbox"
)

type trafficWorker struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	closed bool
}

// ScheduleTraffic performs no network I/O. The immutable disk queue is the
// source of truth, so a restart does not depend on an in-memory wake-up queue.
func (c *APIClient) ScheduleTraffic() error {
	if c.outboxErr != nil {
		return c.outboxErr
	}
	if c.outbox == nil {
		return errors.New("traffic outbox unavailable")
	}
	w := &c.traffic
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("traffic sender stopped")
	}
	if w.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		delay := 10 * time.Second
		for ctx.Err() == nil {
			attempt, stop := context.WithTimeout(ctx, 27*time.Second)
			err := c.outbox.Flush(func(r outbox.Report) error { return c.sendTrafficContext(attempt, &r.Traffic, r.ID) })
			stop()
			if ctx.Err() != nil {
				return
			}
			c.reportFailed.Store(err != nil)
			if err == nil {
				delay = 10 * time.Second
			} else {
				delay = min(delay*2, time.Minute)
			}
			timer := time.NewTimer(delay + time.Duration(rand.Float64()*float64(delay)/5))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return nil
}

// Shutdown cancels the in-flight report, never deletes an unacknowledged ID.
func (c *APIClient) CloseTraffic() {
	w := &c.traffic
	w.mu.Lock()
	w.closed = true
	if w.cancel != nil {
		w.cancel()
	}
	done := w.done
	w.mu.Unlock()
	if done != nil {
		<-done
	}
	if c.client != nil {
		c.client.GetClient().CloseIdleConnections()
	}
}

func (c *APIClient) resetTraffic() {
	c.CloseTraffic()
	w := &c.traffic
	w.mu.Lock()
	w.cancel, w.done, w.closed = nil, nil, false
	w.mu.Unlock()
}
