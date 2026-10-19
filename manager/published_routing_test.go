package manager

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/exitroute"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
)

func TestPublishedSourceAndDestinationRoutesSurviveThirtySecondControlOutage(t *testing.T) {
	t.Parallel()
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}})
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var input conf.InboundDetourConfig
	if err := json.Unmarshal([]byte(`{"protocol":"shadowsocks","tag":"Shadowsocks_31006_17","listen":"127.0.0.1","port":0,"settings":{"method":"aes-128-gcm","password":"test-only-password","network":"tcp,udp"}}`), &input); err != nil {
		t.Fatal(err)
	}
	built, err := input.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := core.AddInboundHandler(m.Server, built); err != nil {
		t.Fatal(err)
	}
	plan := EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa", Outbound: "qa"}}}, Profiles: []EgressProfile{{ID: "qa", Config: json.RawMessage(`{"protocol":"blackhole","settings":{}}`)}}}
	if err := m.ApplyEgress(plan); err != nil {
		t.Fatal(err)
	}
	exit := exitroute.Snapshot{Revision: 1, LeaseSeconds: 30, Rules: []exitroute.Rule{{ID: principalSource, Mode: "shared", Inbound: input.Tag, SourceIP: "10.241.88.1", LocalIP: "10.241.88.2", ExitIP: "192.0.2.146", Active: true}}}
	if err := m.applyExitRoutes(exit, func(netip.Addr) bool { return true }); err != nil {
		t.Fatal(err)
	}
	original := m.Server
	// No control-plane request or local renewal occurs during this interval.
	time.Sleep(31 * time.Second)
	d := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	if _, managed, blocked := d.Egress.Lookup("qa"); !managed || blocked || m.Server != original {
		t.Fatal("source route expired or runtime changed during control outage")
	}
	_, managed, blocked, release := d.ExitRoutes.Acquire(input.Tag, "10.241.88.1", "10.241.88.2")
	release()
	if !managed || blocked {
		t.Fatal("destination route expired during control outage")
	}
	m.RestrictManagedEgress(time.Now().Add(-time.Second))
	m.RestrictExitRoutes(time.Now().Add(-time.Second))
	if _, managed, blocked := d.Egress.Lookup("qa"); !managed || !blocked {
		t.Fatal("explicit source restriction was bypassed")
	}
	_, managed, blocked, release = d.ExitRoutes.Acquire(input.Tag, "10.241.88.1", "10.241.88.2")
	release()
	if !managed || !blocked {
		t.Fatal("explicit destination restriction was bypassed")
	}
}
