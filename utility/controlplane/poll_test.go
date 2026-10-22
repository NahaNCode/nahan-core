package controlplane

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIndependentPollersTimeoutRecoverAndStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	var calls, active, maxActive, heartbeat atomic.Int32
	var healthy atomic.Bool
	workers.Add(2)
	go func() {
		defer workers.Done()
		Poll(ctx, 5*time.Millisecond, 20*time.Millisecond, func(attempt context.Context) error {
			n := active.Add(1)
			defer active.Add(-1)
			if n > maxActive.Load() {
				maxActive.Store(n)
			}
			calls.Add(1)
			if healthy.Load() {
				return nil
			}
			<-attempt.Done()
			return attempt.Err()
		}, func(error) { t.Error("timeout treated as revocation") })
	}()
	go func() {
		defer workers.Done()
		Poll(ctx, 5*time.Millisecond, 20*time.Millisecond, func(context.Context) error {
			heartbeat.Add(1)
			return nil
		}, func(error) { t.Error("heartbeat revoked") })
	}()
	time.Sleep(90 * time.Millisecond)
	if heartbeat.Load() < 5 || maxActive.Load() != 1 || calls.Load() > 5 {
		t.Error("blocked worker leaked or starved heartbeat", heartbeat.Load(), maxActive.Load(), calls.Load())
	}
	healthy.Store(true)
	before := calls.Load()
	time.Sleep(100 * time.Millisecond)
	if calls.Load() <= before {
		t.Error("worker did not recover")
	}
	cancel()
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker failed to stop")
	}
}

func TestPollRevocationIsTerminal(t *testing.T) {
	calls := 0
	var revoked error
	Poll(context.Background(), time.Millisecond, time.Second, func(context.Context) error { calls++; return ErrUnauthorized }, func(err error) { revoked = err })
	if calls != 1 || !errors.Is(revoked, ErrUnauthorized) {
		t.Fatal("revocation was retried or ignored")
	}
}
