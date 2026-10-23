package nahan

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/utility/limiter"
)

func TestDeviceLeaseAdmissionRenewalAndFailure(t *testing.T) {
	var calls atomic.Int32
	var mode atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/api/core/v1/nodes/9/device-leases" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("incorrect authenticated lease endpoint")
		}
		var body struct {
			IDs []int `json:"deviceIds"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.IDs) == 0 {
			t.Error("missing deviceIds")
		}
		if mode.Load() == 1 {
			w.WriteHeader(503)
			return
		}
		grants := []map[string]interface{}{}
		denied := []int{}
		for _, id := range body.IDs {
			if mode.Load() == 2 {
				denied = append(denied, id)
			} else {
				grants = append(grants, map[string]interface{}{"deviceId": id, "expiresAt": time.Now().Unix() + 119})
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
			if !c.AdmitDevice(21) {
				t.Error("admission failed")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("singleflight made %d requests", calls.Load())
	}
	if !c.AdmitDevice(22) {
		t.Fatal("second identity rejected")
	}
	mode.Store(1)
	c.devices.mu.Lock()
	before := c.devices.entries[21].expires
	c.devices.mu.Unlock()
	if c.RenewDevices() == nil {
		t.Fatal("failed renewal succeeded")
	}
	if calls.Load() != 3 {
		t.Fatal("renewal retried or was not batched")
	}
	c.devices.mu.Lock()
	if !c.devices.entries[21].expires.Equal(before) {
		t.Error("failure extended expiry")
	}
	c.devices.entries[21].expires = time.Now().Add(-time.Second)
	c.devices.mu.Unlock()
	if c.ValidDevice(21) || c.AdmitDevice(21) {
		t.Fatal("expired identity admitted")
	}
	if calls.Load() != 3 {
		t.Fatal("expired admission performed HTTP")
	}
	if c.AdmitDevice(23) {
		t.Fatal("unknown identity failed open")
	}
	if calls.Load() != 4 {
		t.Fatal("unknown admission retried")
	}
	mode.Store(2)
	if err := c.RenewDevices(); err != nil {
		t.Fatal(err)
	}
	if c.ValidDevice(22) {
		t.Fatal("explicit denial did not revoke cached lease")
	}
}

func TestDeviceLeaseRejectsInvalidResponses(t *testing.T) {
	for _, body := range []string{
		`{"leaseSeconds":120,"grants":[{"deviceId":999,"expiresAt":%d}],"denied":[]}`,
		`{"leaseSeconds":120,"grants":[{"deviceId":1,"expiresAtUnix":%d}],"denied":[]}`,
		`{"leaseSeconds":120,"grants":[{"deviceId":1,"expiresAt":%d}],"denied":[1]}`,
		`{"leaseSeconds":120,"grants":[],"denied":[]}`,
		`{"leaseSeconds":120,"grants":[{"deviceId":1,"expiresAt":1}],"denied":[]}`,
		`{"leaseSeconds":120,"grants":[{"deviceId":1,"expiresAt":9999999999}],"denied":[]}`,
	} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Replacing only the integer placeholder keeps malformed cases explicit.
				fmtBody := strings.ReplaceAll(body, "%d", strconv.FormatInt(time.Now().Unix()+119, 10))
				w.Write([]byte(fmtBody))
			}))
			defer srv.Close()
			c := New(&api.Config{Protocol: "nahan-v1", APIHost: srv.URL})
			if c.AdmitDevice(1) {
				t.Fatal("invalid response admitted device")
			}
		})
	}
}

func TestDeniedAdmissionRetriesWithBackoffAndSingleflight(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Write([]byte(`{"leaseSeconds":120,"grants":[],"denied":[1]}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"leaseSeconds": 120, "grants": []map[string]interface{}{{"deviceId": 1, "expiresAt": time.Now().Unix() + 119}}, "denied": []int{}})
	}))
	defer srv.Close()
	c := New(&api.Config{Protocol: "nahan-v1", APIHost: srv.URL})
	if c.AdmitDevice(1) || c.AdmitDevice(1) || calls.Load() != 1 {
		t.Fatal("denial backoff bypassed")
	}
	c.devices.mu.Lock()
	c.devices.entries[1].retryAt = time.Now().Add(-time.Second)
	c.devices.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !c.AdmitDevice(1) {
				t.Error("retry failed")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatal("retry not singleflight")
	}
}

func TestRenewalBatchesAtMost512DeviceIDs(t *testing.T) {
	var calls atomic.Int32
	var total atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IDs []int `json:"deviceIds"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if len(body.IDs) == 0 || len(body.IDs) > 512 {
			t.Error("batch exceeds backend limit")
		}
		calls.Add(1)
		total.Add(int32(len(body.IDs)))
		grants := []map[string]interface{}{}
		for _, id := range body.IDs {
			grants = append(grants, map[string]interface{}{"deviceId": id, "expiresAt": time.Now().Unix() + 119})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"leaseSeconds": 120, "grants": grants, "denied": []int{}})
	}))
	defer srv.Close()
	c := New(&api.Config{Protocol: "nahan-v1", APIHost: srv.URL})
	c.devices.entries = map[int]*deviceLease{}
	for id := 1; id <= 1025; id++ {
		c.devices.entries[id] = &deviceLease{active: time.Now()}
	}
	if err := c.RenewDevices(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || total.Load() != 1025 {
		t.Fatal("active devices omitted from renewal")
	}
	for id := 1; id <= 1025; id++ {
		if !c.ValidDevice(id) {
			t.Fatal("batch did not renew device", id)
		}
	}
}

func TestLeaseHTTPTimeoutDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(4 * time.Second):
		}
	}))
	defer srv.Close()
	c := New(&api.Config{Protocol: "nahan-v1", APIHost: srv.URL, Timeout: 10})
	start := time.Now()
	if c.AdmitDevice(1) {
		t.Fatal("timeout failed open")
	}
	if calls.Load() != 1 || time.Since(start) > 3*time.Second {
		t.Fatal("lease deadline or no-retry contract violated")
	}
}

func TestDeviceLeaseFanoutIsBoundedAndSaturationDoesNotRevoke(t *testing.T) {
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	defer releaseOnce.Do(func() { close(release) })
	c := New(&api.Config{Protocol: "nahan-v1", APIHost: srv.URL})
	var wg sync.WaitGroup
	for id := 1; id <= 8; id++ {
		wg.Add(1)
		go func(id int) { defer wg.Done(); c.AdmitDevice(id) }(id)
	}
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("admission workers did not start")
		}
	}
	c.devices.mu.Lock()
	before := time.Now().Add(time.Minute)
	c.devices.entries[90] = &deviceLease{active: time.Now(), expires: before}
	c.devices.mu.Unlock()
	if c.RenewDevices() == nil {
		t.Fatal("saturated renewal was not reported")
	}
	if !c.ValidDevice(90) {
		t.Fatal("saturation revoked an unexpired lease")
	}
	if c.AdmitDevice(91) {
		t.Fatal("saturation invented a grant")
	}
	d := c.DeviceLeaseDiagnostics()
	if d.Saturated != 2 || d.Unavailable != 2 || d.Denied != 0 {
		t.Fatalf("failure incorrectly reported as authorization denial: %+v", d)
	}
	releaseOnce.Do(func() { close(release) })
	wg.Wait()
}

func TestDeviceSubscriptionModeAndLegacyCompatibility(t *testing.T) {
	rows := []Subscription{{Id: 3, ServiceID: 3, DeviceID: 3, DeviceLimit: 1, Email: "same", Uuid: "preserved", Passwd: "preserved", Iplimit: 0, Ipcount: 999},
		{Id: 4, ServiceID: 3, DeviceID: 4, DeviceLimit: 1, Email: "same"}}
	c := New(&api.Config{Protocol: "nahan-v1", APIHost: "http://127.0.0.1"})
	users, err := c.ParseSubscriptionList(&rows)
	if err != nil || len(*users) != 2 {
		t.Fatalf("device list: %v", err)
	}
	a, b := (*users)[0], (*users)[1]
	if a.UID != 3 || a.DeviceID != 3 || a.ServiceID != 3 || a.DeviceLimit != 1 || a.Email == b.Email || a.UUID != "preserved" || a.Passwd != "preserved" {
		t.Fatal("device identity contract lost")
	}
	legacy := New(&api.Config{})
	old, err := legacy.ParseSubscriptionList(&rows)
	if err != nil || (*old)[0].DeviceID != 0 || (*old)[0].Email != "same" || legacy.DeviceGate() != nil {
		t.Fatal("legacy behavior changed")
	}
}

func TestDeviceTelemetryWire(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing authentication")
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		switch r.URL.Path {
		case "/api/core/v1/nodes/9/heartbeat":
			if body["deviceRuntimeVersion"] != float64(1) {
				t.Error("missing device capability")
			}
		case "/api/core/v1/nodes/9/onlineip":
			rows := body["data"].([]interface{})
			row := rows[0].(map[string]interface{})
			if row["subscription_id"] != float64(31) || row["firstSeen"] != float64(100) || row["lastSeen"] != float64(120) || row["routeTag"] != "managed-route" || row["routeRevision"] != float64(42) || row["ip"] != "192.0.2.1" {
				t.Errorf("incorrect telemetry: %v", row)
			}
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ret":1}`))
	}))
	defer srv.Close()
	c := New(&api.Config{Protocol: "nahan-v1", APIHost: srv.URL, NodeID: 9, Key: "secret"})
	if err := c.ReportHeartbeat(); err != nil {
		t.Fatal(err)
	}
	rows := []api.OnlineIP{{UID: 31, IP: "192.0.2.1", FirstSeen: 100, LastSeen: 120, RouteTag: "managed-route", RouteRevision: 42}}
	if err := c.ReportNodeOnlineIPs(&rows); err != nil {
		t.Fatal(err)
	}
}

func TestSameDeviceCredentialRotationInvalidatesOldStreamIdentity(t *testing.T) {
	for _, field := range []string{"uuid", "password"} {
		t.Run(field, func(t *testing.T) {
			c := New(&api.Config{Protocol: "nahan-v1", APIHost: "http://127.0.0.1"})
			rows := []Subscription{{Id: 3, ServiceID: 3, DeviceID: 3, DeviceLimit: 1, Uuid: "old-uuid", Passwd: "old-password"}}
			old, err := c.ParseSubscriptionList(&rows)
			if err != nil {
				t.Fatal(err)
			}
			unchanged, _ := c.ParseSubscriptionList(&rows)
			if (*old)[0].Email != (*unchanged)[0].Email {
				t.Fatal("unchanged snapshot rotated auth generation")
			}
			// A cached device lease survives credential rotation, but old stream
			// admission must not survive its old auth email being removed.
			c.devices.entries = map[int]*deviceLease{3: {expires: time.Now().Add(time.Minute), active: time.Now()}}
			l := limiter.New()
			l.AddInboundLimiter("a", 0, old, nil, c)
			oldEmail := "a|" + (*old)[0].Email + "|3"
			if !l.DeviceValid("a", oldEmail) {
				t.Fatal("old stream not initially valid")
			}
			if field == "uuid" {
				rows[0].Uuid = "new-uuid"
			} else {
				rows[0].Passwd = "new-password"
			}
			rotated, err := c.ParseSubscriptionList(&rows)
			if err != nil {
				t.Fatal(err)
			}
			if (*rotated)[0].Email == (*old)[0].Email || (*rotated)[0].UID != 3 || (*rotated)[0].DeviceID != 3 {
				t.Fatal("rotation did not preserve UID with a new auth generation")
			}
			l.RemoveUser("a", oldEmail)
			l.UpdateInboundLimiter("a", rotated)
			if l.DeviceValid("a", oldEmail) {
				t.Fatal("old stream survived credential rotation")
			}
			if !l.DeviceValid("a", "a|"+(*rotated)[0].Email+"|3") {
				t.Fatal("new credential generation rejected")
			}
		})
	}
}
