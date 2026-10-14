package manager

import (
	"encoding/json"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/features/routing"
	"testing"
	"time"
)

func TestEgressRestoreBeforeInboundsRetainsExpiredLeaseAndCheckIsReadOnly(t *testing.T) {
	plan := EgressPlan{Snapshot: egress.Snapshot{Revision: 4, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa", Outbound: "block"}}}, Profiles: []EgressProfile{{ID: "block", Config: json.RawMessage(`{"protocol":"blackhole","settings":{}}`)}}}
	config := &Config{LogConfig: &LogConfig{Level: "none"}, RestoredEgress: &plan, EgressExpiresAt: time.Now().Add(-time.Minute)}
	m := New(config)
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if !m.HasManagedEgressBindings() {
		t.Fatal("restored binding not visible to revoke guard")
	}
	m.RestrictManagedEgress(time.Now().Add(-time.Second))
	d := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	if _, managed, expired := d.Egress.Lookup("qa"); !managed || !expired {
		t.Fatal("expired persisted route resumed after restart")
	}
	next := plan
	next.Snapshot.Revision = 5
	next.Profiles = []EgressProfile{{ID: "block", Config: json.RawMessage(`{"protocol":"freedom","settings":{}}`)}}
	before := len(m.egress.tags)
	if err := m.CheckEgress(next); err != nil {
		t.Fatal(err)
	}
	if d.Egress.Revision() != 4 || len(m.egress.tags) != before {
		t.Fatal("preflight changed active handlers or routing")
	}
	if _, _, expired := d.Egress.Lookup("qa"); !expired {
		t.Fatal("preflight renewed authorization lease")
	}
	m.Close()
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	d = m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	if _, managed, expired := d.Egress.Lookup("qa"); !managed || !expired {
		t.Fatal("second restart lost protection")
	}
}
