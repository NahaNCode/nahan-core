package controlplane

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"
)

// Poll owns exactly one in-flight attempt, with bounded retry and shutdown.
// Engine mutations must remain on their serialized owner, not in a Poll task.
func Poll(ctx context.Context, interval, budget time.Duration, task func(context.Context) error, revoked func(error)) {
	delay := interval
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, budget)
		err := task(attempt)
		cancel()
		if errors.Is(err, ErrUnauthorized) {
			revoked(err)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			delay = interval
		} else {
			delay = min(delay*2, 4*interval)
		}
		// No immediate catch-up storm after a long timeout or panel recovery.
		pause := delay + time.Duration(rand.Float64()*float64(delay)/5)
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
