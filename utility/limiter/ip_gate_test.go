package limiter

import (
	"testing"

	"github.com/NahaNCode/nahan-core/api"
)

type testIPGate struct {
	testDeviceGate
	allowed bool
	touched bool
}

func (g *testIPGate) AdmitIP(int, string) bool { return g.allowed }
func (g *testIPGate) ValidIP(int, string) bool { return g.allowed }
func (g *testIPGate) TouchIP(int, string)      { g.touched = true }
func (*testIPGate) RenewIPs() error            { return nil }

func TestManagedIPGateIsRequiredAndExplicitDenialInvalidatesExistingFlow(t *testing.T) {
	l := New()
	users := []api.SubscriptionInfo{{UID: 7, ServiceID: 10, Email: "shared", GlobalIPLimit: true, DeviceLimit: 1}}
	if err := l.AddInboundLimiter("a", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, reject := l.GetUserBucket("a", "a|shared|7", "192.0.2.1"); !reject {
		t.Fatal("missing coordinator bypassed")
	}
	gate := &testIPGate{allowed: true}
	if err := l.AddInboundLimiter("a", 0, &users, nil, gate); err != nil {
		t.Fatal(err)
	}
	if _, _, reject := l.GetUserBucket("a", "a|shared|7", "192.0.2.1"); reject {
		t.Fatal("coordinator grant rejected")
	}
	l.TouchOnline("a", "a|shared|7", "192.0.2.1")
	if !gate.touched || !l.ConnectionValid("a", "a|shared|7", "192.0.2.1") {
		t.Fatal("active lease not tracked")
	}
	gate.allowed = false
	if l.ConnectionValid("a", "a|shared|7", "192.0.2.1") {
		t.Fatal("explicit denial left active traffic valid")
	}
	gate.allowed = true
	l.RemoveUser("a", "a|shared|7")
	if l.ConnectionValid("a", "a|shared|7", "192.0.2.1") {
		t.Fatal("revoked credential survived cached IP grant")
	}
}
