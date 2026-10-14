package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func preflightDocument(revision int64) EgressDocument {
	plan := fmt.Sprintf(`{"snapshot":{"revision":%d,"leaseSeconds":30,"bindings":[]},"profiles":[]}`, revision)
	hash := sha256.Sum256([]byte(plan))
	return EgressDocument{Revision: revision, Digest: hex.EncodeToString(hash[:]), PlanJSON: plan}
}

func TestEgressPreflightDoesNotBlockPollingAndDiscardsReplacedCandidate(t *testing.T) {
	var mu sync.Mutex
	var receipts []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var value map[string]any
		if json.NewDecoder(r.Body).Decode(&value) != nil {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		receipts = append(receipts, value)
		mu.Unlock()
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	c := &Client{Config: &Config{APIHost: server.URL, CoreID: "11111111-1111-4111-8111-111111111111"}, Key: "fixture", http: server.Client()}
	defer c.CloseEgressPreflight()
	first, second := preflightDocument(1), preflightDocument(2)
	started, canceled := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	check := func(ctx context.Context) error {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	}
	start := time.Now()
	if err := c.PreparedReceipt(context.Background(), &first, check); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("candidate blocked polling")
	}
	<-started
	for i := 0; i < 10; i++ {
		if err := c.PreparedReceipt(context.Background(), &first, check); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate workers")
	}
	if err := c.PreparedReceipt(context.Background(), &second, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("superseded worker not canceled")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if err := c.PreparedReceipt(context.Background(), &second, func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		count := len(receipts)
		mu.Unlock()
		if count > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("receipt missing")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, receipt := range receipts {
		if receipt["revision"] != float64(2) || receipt["digest"] != second.Digest || receipt["probeRuntimeVersion"] != float64(1) {
			t.Fatal("stale or unverified receipt", receipt)
		}
	}
}

func TestEgressPreflightFailureNeverReportsSuccess(t *testing.T) {
	c := &Client{}
	doc := preflightDocument(1)
	if err := c.PreparedReceipt(context.Background(), &doc, func(context.Context) error { return context.DeadlineExceeded }); err != nil {
		t.Fatal(err)
	}
	c.preflight.mu.Lock()
	attempt := c.preflight.attempt
	c.preflight.mu.Unlock()
	<-attempt.done
	if attempt.code != "preflight_failed" {
		t.Fatal("failure became success")
	}
	c.CloseEgressPreflight()
}
