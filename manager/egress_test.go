package manager

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/egress"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
)

func TestEgressHotSwapPreservesRealStreamAndFailsClosed(t *testing.T) {
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}})
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	original := m.Server
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	plan := func(revision int64, config string) EgressPlan {
		return EgressPlan{
			Snapshot: egress.Snapshot{Revision: revision, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa", Outbound: "qa-profile"}}},
			Profiles: []EgressProfile{{ID: "qa-profile", Config: json.RawMessage(config)}},
		}
	}
	allow := `{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}`
	if err = m.ApplyEgress(plan(1, allow)); err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "qa"})
	target := xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(echo.Addr().(*net.TCPAddr).Port))
	conn, err := core.Dial(ctx, m.Server, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	check := func(conn net.Conn) bool {
		timer := time.AfterFunc(time.Second, func() { conn.Close() })
		defer timer.Stop()
		if _, err := conn.Write([]byte("egress")); err != nil {
			return false
		}
		data := make([]byte, 6)
		_, err := io.ReadFull(conn, data)
		return err == nil && string(data) == "egress"
	}
	if !check(conn) {
		t.Fatal("initial real flow failed")
	}
	if err = m.ApplyEgress(plan(2, `{"protocol":"blackhole","settings":{}}`)); err != nil {
		t.Fatal(err)
	}
	if m.Server != original {
		t.Fatal("egress restarted core")
	}
	if !check(conn) {
		t.Fatal("publishing egress closed old stream")
	}
	blocked, err := core.Dial(ctx, m.Server, target)
	if err == nil {
		defer blocked.Close()
		if check(blocked) {
			t.Fatal("block route fell back to direct")
		}
	}
	invalid := plan(3, allow)
	invalid.Snapshot.Bindings[0].Outbound = "missing"
	if m.ApplyEgress(invalid) == nil {
		t.Fatal("missing outbound accepted")
	}
	dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	if dispatcher.Egress.Revision() != 2 {
		t.Fatal("failed apply changed routing revision")
	}
	if err = m.ApplyEgress(plan(3, allow)); err != nil {
		t.Fatal(err)
	}
	recovered, err := core.Dial(ctx, m.Server, target)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if !check(recovered) || !check(conn) {
		t.Fatal("rollback did not restore new flows and retain old flow")
	}
	if len(m.egress.tags) != 2 {
		t.Fatal("idempotent handler was duplicated")
	}
	withdrawal := EgressPlan{Snapshot: egress.Snapshot{Revision: 4, LeaseSeconds: 30, Bindings: []egress.Binding{}}, Profiles: []EgressProfile{}}
	if err = m.CheckEgress(withdrawal); err != nil {
		t.Fatal("withdrawal preflight failed", err)
	}
	if dispatcher.Egress.Revision() != 3 {
		t.Fatal("withdrawal preflight changed routing")
	}
	if err = m.ApplyEgress(withdrawal); err != nil {
		t.Fatal("withdrawal apply failed", err)
	}
	if _, managed, _ := dispatcher.Egress.Lookup("qa"); managed {
		t.Fatal("withdrawn route retained its binding")
	}
	if m.Server != original || !check(conn) || !check(recovered) {
		t.Fatal("withdrawal restarted engine or interrupted established flows")
	}
	unmanaged, err := core.Dial(ctx, m.Server, target)
	if err != nil {
		t.Fatal("normal routing was not restored after explicit withdrawal", err)
	}
	defer unmanaged.Close()
	if !check(unmanaged) {
		t.Fatal("new flow failed after restoring normal routing")
	}
	if m.ApplyEgress(plan(3, allow)) == nil {
		t.Fatal("older plan revived withdrawn route")
	}
	t.Log("real TCP echo: hot swap, block, failed staging, rollback, withdrawal; old streams preserved")
}
