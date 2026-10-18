package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestEgressHealthIsBoundedScopedAndRateLimited(t *testing.T) {
	received := make(chan struct{}, 2)
	document := preflightDocument(1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/core/v1/cores/core/egress/health" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer key" {
			t.Error("unscoped health report")
		}
		var body struct {
			Revision int64
			Digest   string
			Results  []EgressHealthResult
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Revision != 1 || body.Digest != document.Digest || len(body.Results) != 1 {
			t.Error("health not bound to exact publication")
		}
		w.Write([]byte(`{}`))
		received <- struct{}{}
	}))
	defer server.Close()
	c := &Client{Config: &Config{APIHost: server.URL, CoreID: "core"}, Key: "key", http: server.Client()}
	defer c.CloseEgressHealth()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	check := func(ctx context.Context) []EgressHealthResult {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return []EgressHealthResult{{ProfileID: "route", Alive: true, LatencyMS: 10, CheckedAt: time.Now().UTC()}}
	}
	c.ObserveEgress(&document, check)
	<-started
	for i := 0; i < 10; i++ {
		c.ObserveEgress(&document, check)
	}
	close(release)
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("report missing")
	}
	// Completion updates next before another worker can be started.
	c.health.mu.Lock()
	c.health.next = time.Now().Add(time.Hour)
	c.health.mu.Unlock()
	c.ObserveEgress(&document, check)
	if calls.Load() != 1 {
		t.Fatal("duplicate worker")
	}
}

func TestEgressHealthCancelsWithdrawnPublication(t *testing.T) {
	c := &Client{}
	document := preflightDocument(1)
	started := make(chan struct{})
	finished := make(chan struct{})
	c.ObserveEgress(&document, func(ctx context.Context) []EgressHealthResult {
		close(started)
		<-ctx.Done()
		close(finished)
		return nil
	})
	<-started
	c.CloseEgressHealth()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("worker did not cancel")
	}
	bad := document
	bad.Digest = "tampered"
	c.ObserveEgress(&bad, func(context.Context) []EgressHealthResult { t.Error("invalid plan probed"); return nil })
}
