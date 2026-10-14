package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/routingpolicy"
)

func TestRoutingPolicyStartupWithdrawThenRevoke(t *testing.T) {
	policy, err := routingpolicy.New(routingpolicy.Config{CoreID: "75667842-8144-45a1-b68d-b25d7c617b4a", Key: strings.Repeat("k", 64), Directory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Inspect()
	input, _ := json.Marshal(routingpolicy.Request{CoreID: "75667842-8144-45a1-b68d-b25d7c617b4a", ExpectedDigest: r.Digest, ExpectedGeneration: r.Generation, Enabled: false, Acknowledged: true})
	plan := manager.EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa", Outbound: "block"}}}, Profiles: []manager.EgressProfile{{ID: "block", Config: json.RawMessage(`{"protocol":"blackhole","settings":{}}`)}}}
	cfg := &manager.Config{LogConfig: &manager.LogConfig{Level: "none"}, RestoredEgress: &plan, EgressExpiresAt: time.Now().Add(time.Minute)}
	m := manager.New(cfg)
	const job = "7780f5ce-6e8d-44c7-8830-40d7570bc17b"
	if _, err := applyRoutingPolicy(policy, m, cfg, input, job); err == nil {
		t.Fatal("startup binding revoke accepted")
	}
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := applyRoutingPolicy(policy, m, cfg, input, job); err == nil {
		t.Fatal("live binding revoke accepted")
	}
	if !policy.Inspect().Enabled {
		t.Fatal("rejected revoke changed permission")
	}
	if err := m.ApplyEgress(manager.EgressPlan{Snapshot: egress.Snapshot{Revision: 2, LeaseSeconds: 30}}); err != nil {
		t.Fatal(err)
	}
	if cfg.RestoredEgress == nil || len(cfg.RestoredEgress.Snapshot.Bindings) == 0 {
		t.Fatal("fixture must retain stale restore metadata")
	}
	r, err = applyRoutingPolicy(policy, m, cfg, input, job)
	if err != nil || r.Enabled {
		t.Fatal("withdrawn route could not revoke", err)
	}
}
