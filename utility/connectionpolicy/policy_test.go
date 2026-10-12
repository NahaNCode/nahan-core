package connectionpolicy

import (
	"net/netip"
	"sync"
	"testing"
)

func TestReplacementAndValidation(t *testing.T) {
	var p Policy
	s := Snapshot{Revision: 1, Rules: []Rule{{ID: "exception", Action: "allow", Domains: []string{"ok.example.com"}}, {ID: "deny", Action: "block", Domains: []string{"example.com"}}}}
	if err := p.Replace(s); err != nil {
		t.Fatal(err)
	}
	if !p.Blocked("WWW.EXAMPLE.COM.") || p.Blocked("ok.example.com") || p.Blocked("notexample.com") {
		t.Fatal("domain semantics")
	}
	s.Rules[1].Domains[0] = "other.com"
	if !p.Blocked("example.com") {
		t.Fatal("snapshot was mutable")
	}
	if p.Replace(Snapshot{Revision: 2, Rules: []Rule{{ID: "bad", Action: "block", Domains: []string{"https://example.com"}}}}) == nil {
		t.Fatal("accepted invalid")
	}
	if !p.Blocked("example.com") {
		t.Fatal("invalid update changed policy")
	}
	if err := p.Replace(Snapshot{Revision: 3}); err != nil || p.Blocked("example.com") {
		t.Fatal("clear failed")
	}
}

func TestAdvancedConditionsAreConjunctive(t *testing.T) {
	var p Policy
	rule := Rule{ID: "a", Action: "block", Domains: []string{"example.com"}, DomainMatch: "exact", DestinationIPs: []string{"192.0.2.0/24", "2001:db8::/32"}, Ports: "53,443,1000-2000", Network: "udp"}
	if err := p.Replace(Snapshot{Revision: 1, Rules: []Rule{rule}}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		domain, ip string
		port       uint16
		network    string
		blocked    bool
	}{
		{"example.com", "192.0.2.8", 443, "udp", true}, {"example.com", "2001:db8::1", 1500, "udp", true},
		{"www.example.com", "192.0.2.8", 443, "udp", false}, {"example.com", "198.51.100.1", 443, "udp", false},
		{"example.com", "192.0.2.8", 80, "udp", false}, {"example.com", "192.0.2.8", 443, "tcp", false},
	} {
		if p.BlockedRequest(test.domain, []netip.Addr{netip.MustParseAddr(test.ip)}, test.port, test.network) != test.blocked {
			t.Fatalf("unexpected match %+v", test)
		}
	}
	if p.BlockedRequest("example.com", nil, 443, "udp") {
		t.Fatal("unknown IP matched")
	}
	for _, bad := range []Rule{{ID: "a", Action: "block"}, {ID: "a", Action: "block", Ports: "0"}, {ID: "a", Action: "block", Ports: "100-99"}, {ID: "a", Action: "block", Ports: "65536"}, {ID: "a", Action: "block", DestinationIPs: []string{"example.com"}}, {ID: "a", Action: "block", DestinationIPs: []string{"192.0.2.0/33"}}, {ID: "a", Action: "block", Network: "icmp"}} {
		if Validate(Snapshot{Revision: 2, Rules: []Rule{bad}}) == nil {
			t.Fatalf("accepted invalid %+v", bad)
		}
	}
}
func TestConcurrentUpdates(t *testing.T) {
	var p Policy
	var w sync.WaitGroup
	for i := 0; i < 8; i++ {
		w.Add(1)
		go func() {
			defer w.Done()
			for n := 0; n < 100; n++ {
				_ = p.Replace(Snapshot{Revision: 1, Rules: []Rule{{ID: "a", Action: "block", Domains: []string{"example.com"}}}})
				p.Blocked("example.com")
			}
		}()
	}
	w.Wait()
}
