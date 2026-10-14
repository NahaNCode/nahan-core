package cmd

import (
	"github.com/NahaNCode/nahan-core/manager"
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
