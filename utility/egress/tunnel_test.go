package egress

import "testing"

func TestTunnelBindingRejectsForeignInterfacesAndInvalidInnerPairs(t *testing.T) {
	good := TunnelBinding{ID: routeID, Interface: "nhg333333333333", LocalCIDR: "10.241.87.1/30", PeerIP: "10.241.87.2"}
	if _, _, err := good.Addresses(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*TunnelBinding){
		func(b *TunnelBinding) { b.Interface = "eth0" }, func(b *TunnelBinding) { b.ID = "invalid" },
		func(b *TunnelBinding) { b.LocalCIDR = "10.241.87.1/24" }, func(b *TunnelBinding) { b.PeerIP = "10.241.88.2" },
		func(b *TunnelBinding) { b.PeerIP = "10.241.87.0" }, func(b *TunnelBinding) { b.PeerIP = "10.241.87.3" },
		func(b *TunnelBinding) { b.PeerIP = "10.241.87.1" }, func(b *TunnelBinding) { b.LocalCIDR = "10.241.87.0/30" },
		func(b *TunnelBinding) { b.LocalCIDR = "203.0.113.1/30"; b.PeerIP = "203.0.113.2" },
	} {
		bad := good
		change(&bad)
		if _, _, err := bad.Addresses(); err == nil {
			t.Fatal("invalid tunnel binding accepted", bad)
		}
	}
	if good.VerifyLocal() == nil {
		t.Fatal("nonexistent GRE in core namespace accepted")
	}
}
