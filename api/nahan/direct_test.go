package nahan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NahaNCode/nahan-core/api"
)

func TestDirectNodeAuthenticationAndDurableReplay(t *testing.T) {
	var reportID string
	fail := true
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/core/v1/nodes/900001/traffic" || r.Header.Get("Authorization") != "Bearer test-secret" || r.URL.Query().Get("key") != "" {
			t.Errorf("wrong route or credential transport")
		}
		id := r.Header.Get("Idempotency-Key")
		if reportID == "" {
			reportID = id
		}
		if id == "" || id != reportID {
			t.Errorf("report ID changed")
		}
		var payload PostData
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		if fail {
			w.WriteHeader(503)
			w.Write([]byte(`{"error":"temporary"}`))
			return
		}
		w.Write([]byte(`{"ret":1}`))
	}))
	defer server.Close()
	cfg := &api.Config{APIHost: server.URL, NodeID: 900001, Key: "test-secret", Protocol: "nahan-v1", TrafficOutboxDir: t.TempDir()}
	client := New(cfg)
	client.client.SetRetryCount(0)
	traffic := []api.SubscriptionTraffic{{UID: 1000001, Upload: 100, Download: 200}}
	if err := client.QueueTraffic(&traffic); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("enqueue performed network I/O")
	}
	if err := client.FlushTraffic(); err == nil {
		t.Fatal("expected delivery error")
	}
	client = New(cfg)
	client.client.SetRetryCount(0)
	fail = false
	if err := client.FlushTraffic(); err != nil {
		t.Fatal(err)
	}
	if n, err := client.outbox.Pending(); err != nil || n != 0 {
		t.Fatalf("undrained queue: %d %v", n, err)
	}
	if calls != 2 {
		t.Fatal("unexpected report count")
	}
}
