package xdispatcher

import (
	"context"
	"github.com/xtls/xray-core/transport"
	"sync/atomic"
	"testing"
)

func TestRevokeClosesExistingAndRacingSessionsOnlyForService(t *testing.T) {
	d := &DefaultDispatcher{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var closed atomic.Int32
	d.trackSession(ctx, "service-a", &transport.Link{}, func() { closed.Add(1) })
	d.trackSession(ctx, "service-b", &transport.Link{}, func() { t.Error("unrelated service revoked") })
	d.RevokeUser("service-a")
	d.trackSession(ctx, "service-a", &transport.Link{}, func() { closed.Add(1) })
	if closed.Load() != 2 {
		t.Fatal("existing or racing session remained open")
	}
	d.AllowUser("service-a")
	d.trackSession(ctx, "service-a", &transport.Link{}, func() { closed.Add(1) })
	if closed.Load() != 2 {
		t.Fatal("reenabled service rejected")
	}
	d.RevokeUser("service-a")
	if closed.Load() != 3 {
		t.Fatal("reenabled session not tracked")
	}
}
