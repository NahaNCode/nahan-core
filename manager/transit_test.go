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
	"github.com/xtls/xray-core/infra/conf"
)

func TestTransitNeverFallsBackBeforeApplyAfterExpiryOrAfterWithdrawal(t *testing.T) {
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}, ResolveEgressCredential: func(egress.CredentialBinding) (egress.SSCredential, error) {
		return egress.SSCredential{Method: "aes-128-gcm", Password: "test-transit-password"}, nil
	}})
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	d := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	if err := d.RequireTransit("qa-transit"); err != nil {
		t.Fatal(err)
	}
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
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "qa-transit"})
	target := xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(echo.Addr().(*net.TCPAddr).Port))
	check := func(conn net.Conn) bool {
		timer := time.AfterFunc(time.Second, func() { conn.Close() })
		defer timer.Stop()
		if _, err := conn.Write([]byte("transit")); err != nil {
			return false
		}
		data := make([]byte, 7)
		_, err := io.ReadFull(conn, data)
		return err == nil && string(data) == "transit"
	}
	blocked := func() {
		t.Helper()
		conn, err := core.Dial(ctx, m.Server, target)
		if err == nil {
			defer conn.Close()
			if check(conn) {
				t.Fatal("transit fell back to direct")
			}
		}
	}
	blocked()
	plan := EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa-transit", Outbound: "next-hop"}}}, Profiles: []EgressProfile{{ID: "next-hop", Config: json.RawMessage(`{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}`)}}}
	if m.ApplyEgress(plan) == nil {
		t.Fatal("transit accepted a direct Internet exit")
	}
	portSocket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portSocket.Addr().(*net.TCPAddr).Port
	portSocket.Close()
	raw, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "shadowsocks", "settings": map[string]any{"method": "aes-128-gcm", "password": "test-transit-password", "network": "tcp"}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}}})
	var peerConfig conf.Config
	if err = json.Unmarshal(raw, &peerConfig); err != nil {
		t.Fatal(err)
	}
	built, err := peerConfig.Build()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = peer.Start(); err != nil {
		t.Fatal(err)
	}
	client, _ := json.Marshal(map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": port, "method": "aes-128-gcm"}}}})
	plan.Profiles[0].Config = client
	plan.Profiles[0].ID = principalRoute
	plan.Snapshot.Bindings[0].Outbound = principalRoute
	plan.Profiles[0].Secret = &egress.CredentialBinding{RouteID: principalRoute, TransferID: principalCustomer, Revision: 1, Method: "aes-128-gcm"}
	if err = m.ApplyEgress(plan); err != nil {
		t.Fatal(err)
	}
	conn, err := core.Dial(ctx, m.Server, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !check(conn) {
		t.Fatal("valid transit next hop failed")
	}
	d.Egress.RestrictLease(time.Now().Add(-time.Second))
	blocked()
	if !check(conn) {
		t.Fatal("lease expiry interrupted existing flow")
	}
	if err = m.ApplyEgress(EgressPlan{Snapshot: egress.Snapshot{Revision: 2, LeaseSeconds: 30, Bindings: []egress.Binding{}}, Profiles: []EgressProfile{}}); err != nil {
		t.Fatal(err)
	}
	blocked()
	if !check(conn) {
		t.Fatal("withdrawal interrupted retained flow")
	}
	if !d.TransitRequired("qa-transit") || d.TransitRequired("customer") {
		t.Fatal("transit role changed unrelated input")
	}
}
