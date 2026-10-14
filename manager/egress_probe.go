package manager

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
)

// ProbeEgressProfile uses the real host namespace and engine transport without
// installing handlers or changing routing in the customer-serving engine.
func (m *Manager) ProbeEgressProfile(parent context.Context, p EgressProfile, check func(context.Context, string, string, string) error) error {
	if check == nil || (p.Principal == nil && p.Secret == nil) {
		return errors.New("managed path probe unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	password := base64.RawURLEncoding.EncodeToString(random[:])
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := reserved.Addr().String()
	port := reserved.Addr().(*net.TCPAddr).Port
	if err := reserved.Close(); err != nil {
		return err
	}
	probe := New(&Config{LogConfig: &LogConfig{Level: "none"}, ResolveEgressPrincipal: m.managerConfig.ResolveEgressPrincipal, ResolveEgressCredential: m.managerConfig.ResolveEgressCredential})
	if err := probe.StartChecked(); err != nil {
		return err
	}
	defer probe.Close()
	const tag = "nahan-egress-probe"
	const username = "nahan-egress/probe"
	if err := probe.ApplyEgress(EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: tag, Outbound: p.ID}}}, Profiles: []EgressProfile{p}}); err != nil {
		return err
	}
	dispatcher := probe.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	users := []api.SubscriptionInfo{}
	if err := dispatcher.Limiter.AddInboundLimiter(tag, 0, &users, nil); err != nil {
		return err
	}
	if err := dispatcher.Limiter.AddInfrastructureUser(tag, username); err != nil {
		return err
	}
	data, err := json.Marshal(map[string]any{"protocol": "socks", "tag": tag, "listen": "127.0.0.1", "port": port, "settings": map[string]any{"auth": "password", "udp": false, "accounts": []any{map[string]any{"user": username, "pass": password}}}})
	if err != nil {
		return err
	}
	var inbound conf.InboundDetourConfig
	if err := json.Unmarshal(data, &inbound); err != nil {
		return err
	}
	built, err := inbound.Build()
	if err != nil {
		return err
	}
	if err := core.AddInboundHandler(probe.Server, built); err != nil {
		return err
	}
	return check(ctx, address, username, password)
}
