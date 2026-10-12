package nahan

import (
	"encoding/json"
	"github.com/NahaNCode/nahan-core/api"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthorizationAcknowledgesOnlyAppliedSnapshots(t *testing.T) {
	revision, lease := int64(7), 30
	var heartbeat map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/core/v1/nodes/1/heartbeat" {
			json.NewDecoder(r.Body).Decode(&heartbeat)
			w.Write([]byte(`{"ret":1}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"authorizationRevision": revision, "leaseSeconds": lease, "subscriptions": []Subscription{{Id: 1, Uuid: "11111111-1111-4111-8111-111111111111", Email: "service", Speedlimit: 0.5, Iplimit: 1}}})
	}))
	defer server.Close()
	client := New(&api.Config{APIHost: server.URL, NodeID: 1, Protocol: "nahan-v1", Key: "test"})
	users, err := client.GetSubscriptionList()
	if err != nil {
		t.Fatal(err)
	}
	if (*users)[0].SpeedLimit != 62500 {
		t.Fatal("fractional per-core speed lost")
	}
	if !client.AuthorizationLease().After(time.Now()) {
		t.Fatal("missing lease")
	}
	client.ReportHeartbeat()
	if heartbeat["servicesSynced"] != false || heartbeat["authorizationRevision"] != float64(0) {
		t.Fatal("fetched snapshot incorrectly acknowledged")
	}
	client.MarkSubscriptionsApplied()
	client.ReportHeartbeat()
	if heartbeat["servicesSynced"] != true || heartbeat["authorizationRevision"] != float64(7) {
		t.Fatal("applied revision not acknowledged")
	}
	revision = 6
	if _, err = client.GetSubscriptionList(); err == nil {
		t.Fatal("stale authorization accepted")
	}
	revision = 8
	lease = 121
	if _, err = client.GetSubscriptionList(); err == nil {
		t.Fatal("unbounded offline lease accepted")
	}
}
