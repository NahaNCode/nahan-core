package egress

import "testing"

func TestRoutingPolicyGuardTracksWithdrawal(t *testing.T) {
	r := &Registry{}
	if r.HasBindings() {
		t.Fatal("empty registry has bindings")
	}
	if err := r.Replace(Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []Binding{{Inbound: "qa", Outbound: "test"}}}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if !r.HasBindings() {
		t.Fatal("published binding absent")
	}
	if err := r.Replace(Snapshot{Revision: 2, LeaseSeconds: 30}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if r.HasBindings() {
		t.Fatal("withdrawn binding still present")
	}
}
