package manager

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/exitroute"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
)

func TestDestinationExitHandlersInstallWithoutRestartAndRemainFailClosed(t *testing.T) {
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}})
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	original := m.Server
	var input conf.InboundDetourConfig
	if err := json.Unmarshal([]byte(`{"protocol":"shadowsocks","tag":"Shadowsocks_31006_17","listen":"127.0.0.1","port":0,"settings":{"method":"aes-128-gcm","password":"test-only-password","network":"tcp,udp"}}`), &input); err != nil {
		t.Fatal(err)
	}
	built, err := input.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err = core.AddInboundHandler(m.Server, built); err != nil {
		t.Fatal(err)
	}
	s := exitroute.Snapshot{Revision: 1, LeaseSeconds: 30, Rules: []exitroute.Rule{
		{ID: principalSource, Mode: "shared", Inbound: input.Tag, SourceIP: "10.241.88.1", LocalIP: "10.241.88.2", ExitIP: "192.0.2.146", Active: true},
		{ID: principalTarget, Mode: "shared", Inbound: input.Tag, SourceIP: "10.241.87.1", LocalIP: "10.241.87.2", ExitIP: "192.0.2.197", Active: true},
	}}
	if err = m.applyExitRoutes(s, func(netip.Addr) bool { return true }); err != nil {
		t.Fatal(err)
	}
	d := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	outputs := m.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	tags := map[string]bool{}
	for _, rule := range s.Rules {
		tag, managed, expired, release := d.ExitRoutes.Acquire(input.Tag, rule.SourceIP, rule.LocalIP)
		release()
		if !managed || expired || outputs.GetHandler(tag) == nil {
			t.Fatal("destination handler not installed", tag)
		}
		tags[tag] = true
	}
	if len(tags) != 2 || m.Server != original {
		t.Fatal("exit handlers aliased or engine restarted")
	}
	s.Revision = 2
	s.Rules[0].ExitIP = "192.0.2.99"
	if m.applyExitRoutes(s, func(a netip.Addr) bool { return a.String() != "192.0.2.99" }) == nil {
		t.Fatal("unowned IP accepted")
	}
	m.RestrictExitRoutes(time.Now().Add(-time.Second))
	_, managed, expired, release := d.ExitRoutes.Acquire(input.Tag, "10.241.88.1", "10.241.88.2")
	release()
	if !managed || !expired {
		t.Fatal("expired exit fell back")
	}
}
