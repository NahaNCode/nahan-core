package cmd

import (
	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"testing"
)

func TestPersonalOutboundInventoryDoesNotDisableManagedRouting(t *testing.T) {
	config := &manager.Config{OutboundConfigPath: "/private/outbound.json"}
	if incompatibleManagedRouting(config) {
		t.Fatal("outbound inventory is not a routing override")
	}
	for _, config := range []*manager.Config{{RouteConfigPath: "/route"}, {DnsConfigPath: "/dns"}, {InboundConfigPath: "/inbound"}} {
		if !incompatibleManagedRouting(config) {
			t.Fatal("custom routing override accepted")
		}
	}
}

func TestExistingRoutingRequiresExplicitManagedEgressAcknowledgement(t *testing.T) {
	config := &manager.Config{RouteConfigPath: "/route", ControlPlane: &controlplane.Config{AllowManagedEgress: true}}
	if incompatibleManagedRouting(config) {
		t.Fatal("explicit scoped override rejected")
	}
	config.InboundConfigPath = "/inbound"
	if !incompatibleManagedRouting(config) {
		t.Fatal("custom inbound isolation bypassed")
	}
}
