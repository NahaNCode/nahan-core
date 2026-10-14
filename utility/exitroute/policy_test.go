package exitroute

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/utility/egress"
)

const first = "11111111-1111-4111-8111-111111111111"
const second = "22222222-2222-4222-8222-222222222222"

func owned(ip netip.Addr) bool {
	return ip == netip.MustParseAddr("192.0.2.146") || ip == netip.MustParseAddr("192.0.2.197") || ip == netip.MustParseAddr("10.241.88.2") || ip == netip.MustParseAddr("10.241.87.2")
}
func shared() Snapshot {
	return Snapshot{Revision: 1, LeaseSeconds: 30, Rules: []Rule{
		{ID: first, Mode: "shared", Inbound: "Shadowsocks_31006_17", SourceIP: "10.241.88.1", LocalIP: "10.241.88.2", ExitIP: "192.0.2.146", Active: true},
		{ID: second, Mode: "shared", Inbound: "Shadowsocks_31006_17", SourceIP: "10.241.87.1", LocalIP: "10.241.87.2", ExitIP: "192.0.2.197", Active: true},
	}}
}
func install(s egress.Snapshot, r *egress.Registry) error {
	for i := range s.Bindings {
		s.Bindings[i].Outbound = "handler-" + s.Bindings[i].Outbound
	}
	return r.Replace(s, func(string) bool { return true })
}
func TestSharedPortSeparatesTunnelEndpointsAndLeavesOthersUnchanged(t *testing.T) {
	var p Policy
	if err := p.Apply(shared(), owned, install); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ source, local, id string }{{"10.241.88.1", "10.241.88.2", first}, {"10.241.87.1", "10.241.87.2", second}} {
		tag, managed, expired, release := p.Acquire("Shadowsocks_31006_17", item.source, item.local)
		if tag != "handler-"+item.id || !managed || expired {
			t.Fatal(tag, managed, expired)
		}
		release()
	}
	_, managed, _, release := p.Acquire("Shadowsocks_31006_17", "10.241.89.1", "10.241.89.2")
	release()
	if managed {
		t.Fatal("unselected tunnel changed")
	}
	_, managed, expired, release := p.Acquire("Shadowsocks_31006_17", "10.241.88.1", "")
	release()
	if !managed || !expired {
		t.Fatal("missing socket identity silently fell back")
	}
}
func TestIndependentPortsHaveIndependentExitIPs(t *testing.T) {
	s := shared()
	for i := range s.Rules {
		s.Rules[i].Mode = "independent"
		s.Rules[i].SourceIP = ""
		s.Rules[i].LocalIP = ""
	}
	s.Rules[1].Inbound = "Shadowsocks_31007_18"
	var p Policy
	if err := p.Apply(s, owned, install); err != nil {
		t.Fatal(err)
	}
	for i, rule := range s.Rules {
		tag, managed, expired, release := p.Acquire(rule.Inbound, "203.0.113.10", "")
		release()
		if !managed || expired || tag != "handler-"+s.Rules[i].ID {
			t.Fatal(tag, managed, expired)
		}
	}
}

func TestWildcardUDPSelectorsRemainDistinct(t *testing.T) {
	var p Policy
	if err := p.Apply(shared(), owned, install); err != nil {
		t.Fatal(err)
	}
	for _, local := range []string{"0.0.0.0", "::"} {
		for _, r := range shared().Rules {
			tag, managed, expired, release := p.Acquire(r.Inbound, r.SourceIP, local)
			release()
			if tag != "handler-"+r.ID || !managed || expired {
				t.Fatal("wildcard selector misrouted", tag, managed, expired)
			}
		}
	}
}

func TestRestoredExpiredAndInactiveSelectorsNeverFallBack(t *testing.T) {
	var p Policy
	if err := p.Reserve(shared()); err != nil {
		t.Fatal(err)
	}
	checkBlocked := func() {
		t.Helper()
		_, managed, expired, release := p.Acquire("Shadowsocks_31006_17", "10.241.88.1", "10.241.88.2")
		release()
		if !managed || !expired {
			t.Fatal("selected traffic fell back")
		}
	}
	checkBlocked()
	if err := p.Apply(shared(), owned, install); err != nil {
		t.Fatal(err)
	}
	p.RestrictLease(time.Now().Add(-time.Second))
	checkBlocked()
	s := shared()
	s.Revision = 2
	s.Rules[0].Active = false
	if err := p.Apply(s, owned, install); err != nil {
		t.Fatal(err)
	}
	checkBlocked()
}
func TestRejectsAmbiguousSelectorsForeignIPsAndMixedModes(t *testing.T) {
	for _, change := range []func(*Snapshot){
		func(s *Snapshot) { s.Rules[1].SourceIP = s.Rules[0].SourceIP; s.Rules[1].LocalIP = s.Rules[0].LocalIP },
		func(s *Snapshot) { s.Rules[0].ExitIP = "192.0.2.99" },
		func(s *Snapshot) { s.Rules[0].LocalIP = "10.241.99.2" },
		func(s *Snapshot) { s.Rules[0].Mode = "independent"; s.Rules[0].SourceIP = ""; s.Rules[0].LocalIP = "" },
		func(s *Snapshot) { s.Rules[0].ExitIP = "127.0.0.1" },
		func(s *Snapshot) { s.Rules[1].ID = s.Rules[0].ID },
	} {
		s := shared()
		change(&s)
		if Validate(s, owned) == nil {
			t.Fatal("invalid snapshot accepted", s)
		}
	}
}
func TestFailedInstallAndStaleRevisionLeavePreviousSelection(t *testing.T) {
	var p Policy
	if err := p.Apply(shared(), owned, install); err != nil {
		t.Fatal(err)
	}
	s := shared()
	s.Revision = 2
	s.Rules[0].SourceIP = "10.241.88.3"
	if p.Apply(s, owned, func(egress.Snapshot, *egress.Registry) error { return errors.New("install failed") }) == nil {
		t.Fatal("failure accepted")
	}
	tag, managed, _, release := p.Acquire("Shadowsocks_31006_17", "10.241.88.1", "10.241.88.2")
	release()
	if !managed || tag != "handler-"+first {
		t.Fatal("old selection changed")
	}
}
