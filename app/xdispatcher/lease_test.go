package xdispatcher

import (
	"context"
	"github.com/xtls/xray-core/transport"
	"testing"
	"time"
)

func TestExpiredLeaseClosesLiveAndRacingSessions(t *testing.T) {
	d := &DefaultDispatcher{}
	closed := make(chan struct{}, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.LeaseUser("a|service|1", time.Now().Add(30*time.Millisecond))
	d.trackSession(ctx, "a|service|1", &transport.Link{}, func() { closed <- struct{}{} })
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("offline lease did not close stream")
	}
	d.trackSession(ctx, "a|service|1", &transport.Link{}, func() { closed <- struct{}{} })
	select {
	case <-closed:
	default:
		t.Fatal("expired credential accepted racing stream")
	}
}

func TestRenewedLeaseSurvivesOldExpiryAndKeepsOtherInboundIndependent(t *testing.T) {
	d := &DefaultDispatcher{}
	old := time.Now().Add(30 * time.Millisecond)
	d.LeaseUser("a|service|1", old)
	d.LeaseUser("a|service|1", time.Now().Add(time.Second))
	d.LeaseUser("b|service|1", time.Now().Add(time.Second))
	time.Sleep(60 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := make(chan struct{}, 2)
	d.trackSession(ctx, "a|service|1", &transport.Link{}, func() { closed <- struct{}{} })
	select {
	case <-closed:
		t.Fatal("old timer revoked renewed lease")
	default:
	}
	d.trackSession(ctx, "b|service|1", &transport.Link{}, func() { t.Error("other inbound revoked") })
	d.RevokeUser("a|service|1")
	select {
	case <-closed:
	default:
		t.Fatal("revoked membership retained live stream")
	}
}
