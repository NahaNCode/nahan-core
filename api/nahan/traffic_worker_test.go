package nahan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/api"
)

func TestTrafficWorkerIsIndependentDurableAndCancellable(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		once.Do(func() { close(started) })
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	client := New(&api.Config{APIHost: server.URL, NodeID: 1, Key: "test", Protocol: "nahan-v1", TrafficOutboxDir: t.TempDir()})
	defer client.CloseTraffic()
	rows := []api.SubscriptionTraffic{{UID: 1, Upload: 100}}
	if err := client.QueueTraffic(&rows); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := client.ScheduleTraffic(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("traffic worker did not start")
	}
	if err := client.QueueTraffic(&rows); err != nil {
		t.Fatal("new report blocked", err)
	}
	done := make(chan struct{})
	go func() { client.CloseTraffic(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("traffic shutdown not cancelable")
	}
	if n, err := client.outbox.Pending(); err != nil || n != 2 {
		t.Fatal("unacknowledged usage lost", n, err)
	}
	if client.ScheduleTraffic() == nil {
		t.Fatal("closed client restarted sender")
	}
	client.resetTraffic()
}

func TestNativeTransportDoesNotAddRestyRetries(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer server.Close()
	client := New(&api.Config{APIHost: server.URL, NodeID: 1, Key: "test", Protocol: "nahan-v1", TrafficOutboxDir: t.TempDir()})
	rows := []api.SubscriptionTraffic{{UID: 1, Upload: 100}}
	if err := client.QueueTraffic(&rows); err != nil {
		t.Fatal(err)
	}
	if client.FlushTraffic() == nil {
		t.Fatal("lost acknowledgement considered delivered")
	}
	if calls.Load() != 1 {
		t.Fatal("transport replayed beyond verified retry policy", calls.Load())
	}
	if n, _ := client.outbox.Pending(); n != 1 {
		t.Fatal("unacknowledged report deleted")
	}
}
