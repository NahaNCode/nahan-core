package nahan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/api"
)

func TestManagedIPLeaseSingleflightRenewalAndUnavailable(t *testing.T) {
	var calls, mode atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/core/v1/nodes/9/ip-leases" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("incorrect authenticated IP endpoint")
		}
		var request struct {
			Entries []ipKey `json:"entries"`
			Renew   bool    `json:"renew"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid request")
		}
		if mode.Load() == 1 {
			w.WriteHeader(503)
			return
		}
		grants := []map[string]interface{}{}
		denied := []ipKey{}
		for _, key := range request.Entries {
			if mode.Load() == 2 {
				denied = append(denied, key)
			} else {
				grants = append(grants, map[string]interface{}{"subscriptionId": key.ID, "ip": key.IP, "expiresAt": time.Now().Unix() + 119})
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"leaseSeconds": 120, "grants": grants, "denied": denied})
	}))
	defer srv.Close()
	c := New(&api.Config{Protocol: "nahan-v1", APIHost: srv.URL, NodeID: 9, Key: "secret"})
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !c.AdmitIP(1, "::ffff:192.0.2.1") {
				t.Error("initial admission rejected")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 || !c.AdmitIP(1, "192.0.2.1") {
		t.Fatal("canonical identity was not singleflight")
	}
	key := ipKey{1, "192.0.2.1"}
	c.ips.mu.Lock()
	before := c.ips.entries[key].expires
	c.ips.mu.Unlock()
	mode.Store(1)
	if c.RenewIPs() == nil || !c.validIP(key) {
		t.Fatal("unavailability revoked existing lease")
	}
	c.ips.mu.Lock()
	unchanged := c.ips.entries[key].expires.Equal(before)
	c.ips.mu.Unlock()
	if !unchanged || c.AdmitIP(2, "192.0.2.2") {
		t.Fatal("unavailability extended or invented a lease")
	}
	mode.Store(2)
	if err := c.RenewIPs(); err != nil {
		t.Fatal(err)
	}
	if c.validIP(key) {
		t.Fatal("explicit denial ignored")
	}
}

func TestManagedIPLeaseInvalidRepliesNeverGrant(t *testing.T) {
	for _, body := range []string{
		`{"leaseSeconds":120,"grants":[],"denied":[]}`,
		`{"leaseSeconds":120,"grants":[{"subscriptionId":99,"ip":"192.0.2.1","expiresAt":9999999999}],"denied":[]}`,
		`{"leaseSeconds":120,"grants":[],"denied":[{"subscriptionId":1,"ip":"host.invalid"}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer srv.Close()
			c := New(&api.Config{Protocol: "nahan-v1", APIHost: srv.URL})
			if c.AdmitIP(1, "192.0.2.1") {
				t.Fatal("invalid reply granted IP")
			}
		})
	}
}

func TestManagedIPSubscriptionIsOptInAndPreservesLegacyIdentity(t *testing.T) {
	c := New(&api.Config{Protocol: "nahan-v1", APIHost: "http://127.0.0.1"})
	rows := []Subscription{{Id: 3, ServiceID: 8, GlobalIPLimit: true, Iplimit: 2, Email: "legacy", Uuid: "unchanged"}}
	users, err := c.ParseSubscriptionList(&rows)
	if err != nil {
		t.Fatal(err)
	}
	u := (*users)[0]
	if !u.GlobalIPLimit || u.ServiceID != 8 || u.DeviceID != 0 || u.UUID != "unchanged" || u.Email != "legacy" {
		t.Fatal("shared credential changed mode or identity")
	}
	rows[0].GlobalIPLimit = false
	users, err = c.ParseSubscriptionList(&rows)
	if err != nil || (*users)[0].GlobalIPLimit {
		t.Fatal("opt-out not preserved")
	}
}
