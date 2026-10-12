package limiter

import (
	"context"
	"errors"
	"golang.org/x/time/rate"
	"testing"
	"time"
)

func TestNonzeroServiceLimitWithUnlimitedNode(t *testing.T) {
	for _, tc := range []struct{ node, user, want uint64 }{{0, 200, 200}, {200, 0, 200}, {0, 0, 0}, {100, 200, 100}, {200, 100, 100}} {
		if got := determineRate(tc.node, tc.user); got != tc.want {
			t.Fatalf("rate(%d,%d)=%d want %d", tc.node, tc.user, got, tc.want)
		}
	}
}
func TestPayloadLargerThanBurstIsThrottled(t *testing.T) {
	bucket := rate.NewLimiter(1000, 100)
	start := time.Now()
	if err := waitBytes(context.Background(), bucket, 300); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 180*time.Millisecond {
		t.Fatal("oversized payload bypassed throttle")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitBytes(ctx, bucket, 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not propagated: %v", err)
	}
}
