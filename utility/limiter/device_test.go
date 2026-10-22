package limiter

import (
	"fmt"
	"sync"
	"testing"

	"github.com/NahaNCode/nahan-core/api"
)

type testDeviceGate struct {
	mu      sync.Mutex
	allowed map[int]bool
	seen    map[int]bool
}

func (g *testDeviceGate) AdmitDevice(id int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen[id] = true
	return g.allowed[id]
}
func (g *testDeviceGate) ValidDevice(id int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.allowed[id]
}
func (*testDeviceGate) TouchDevice(int)     {}
func (*testDeviceGate) RenewDevices() error { return nil }

func TestRegisteredDevicesIgnoreIPAndShareServiceSpeed(t *testing.T) {
	l := New()
	gate := &testDeviceGate{allowed: map[int]bool{11: true, 12: true}, seen: map[int]bool{}}
	users := []api.SubscriptionInfo{{UID: 11, ServiceID: 5, DeviceID: 11, Email: "d11", SpeedLimit: 1000, DeviceLimit: 1},
		{UID: 12, ServiceID: 5, DeviceID: 12, Email: "d12", SpeedLimit: 1000, DeviceLimit: 1},
		{UID: 13, ServiceID: 5, DeviceID: 13, Email: "d13", SpeedLimit: 1000, DeviceLimit: 1}}
	for _, tag := range []string{"a", "b"} {
		if err := l.AddInboundLimiter(tag, 0, &users, nil, gate); err != nil {
			t.Fatal(err)
		}
	}
	a, limited, reject := l.GetUserBucket("a", "a|d11|11", "192.0.2.1")
	if !limited || reject {
		t.Fatal("device rejected")
	}
	b, _, reject := l.GetUserBucket("b", "b|d11|11", "192.0.2.2")
	if reject || a != b {
		t.Fatal("IP change broke device or shared bucket")
	}
	b, _, reject = l.GetUserBucket("b", "b|d12|12", "192.0.2.1")
	if reject || a != b || len(gate.seen) != 2 {
		t.Fatal("two IDs on one IP not independently gated or service speed split")
	}
	if _, _, reject = l.GetUserBucket("b", "b|d13|13", "192.0.2.1"); !reject {
		t.Fatal("backend denial ignored")
	}
	if _, loaded := l.serviceIPs.Load("service:5"); loaded {
		t.Fatal("device used IP counting")
	}
	l.RemoveUser("a", "a|d11|11")
	if l.DeviceValid("a", "a|d11|11") || !l.DeviceValid("b", "b|d11|11") {
		t.Fatal("assignment revocation disturbed another inbound")
	}
	gate.mu.Lock()
	gate.allowed[11] = false
	gate.mu.Unlock()
	if l.DeviceValid("b", "b|d11|11") {
		t.Fatal("cached gate denial ignored")
	}
	for i := range users {
		users[i].SpeedLimit = 500
	}
	if err := l.UpdateInboundLimiter("b", &users); err != nil {
		t.Fatal(err)
	}
	if a.Limit() != 500 {
		t.Fatal("service speed update did not reach shared bucket")
	}
}

func TestDevicePresenceBoundedConcurrentRouteVersions(t *testing.T) {
	l := New()
	gate := &testDeviceGate{allowed: map[int]bool{11: true}, seen: map[int]bool{}}
	users := []api.SubscriptionInfo{{UID: 11, ServiceID: 5, DeviceID: 11, Email: "d11"}}
	l.AddInboundLimiter("a", 0, &users, nil, gate)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.GetUserBucket("a", "a|d11|11", "192.0.2.1")
			l.TouchOnlineRoute("a", "a|d11|11", "192.0.2.1", fmt.Sprintf("route-%d", i), int64(i+1))
			l.GetOnlineDevice("a")
		}(i)
	}
	wg.Wait()
	rows, err := l.GetOnlineDevice("a")
	if err != nil || len(*rows) > 64 || len(*rows) < 2 {
		t.Fatalf("unbounded or missing route observations: %v", err)
	}
	for _, r := range *rows {
		if r.UID != 11 || r.IP != "192.0.2.1" || r.FirstSeen <= 0 || r.LastSeen < r.FirstSeen || r.RouteRevision <= 0 {
			t.Fatalf("invalid observation: %+v", r)
		}
	}
}

func TestDeviceModeWithoutGateFailsClosed(t *testing.T) {
	l := New()
	users := []api.SubscriptionInfo{{UID: 1, ServiceID: 1, DeviceID: 1, Email: "d"}}
	l.AddInboundLimiter("a", 0, &users, nil)
	if _, _, reject := l.GetUserBucket("a", "a|d|1", "192.0.2.1"); !reject {
		t.Fatal("missing device gate failed open")
	}
}

func TestSharedCredentialAndRegisteredDeviceUseSameServiceRate(t *testing.T) {
	l := New()
	gate := &testDeviceGate{allowed: map[int]bool{12: true}, seen: map[int]bool{}}
	users := []api.SubscriptionInfo{
		{UID: 5, ServiceID: 5, Email: "shared", SpeedLimit: 1000},
		{UID: 12, ServiceID: 5, DeviceID: 12, Email: "device", SpeedLimit: 1000},
	}
	if err := l.AddInboundLimiter("a", 0, &users, nil, gate); err != nil {
		t.Fatal(err)
	}
	shared, _, reject := l.GetUserBucket("a", "a|shared|5", "192.0.2.1")
	if reject {
		t.Fatal("shared credential rejected")
	}
	device, _, reject := l.GetUserBucket("a", "a|device|12", "192.0.2.1")
	if reject || shared != device {
		t.Fatal("shared and registered credentials multiplied the service rate")
	}
}
