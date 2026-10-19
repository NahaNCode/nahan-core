package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/features/routing"
)

func TestLiveEgressRenewalDoesNotDependOnCredentialDelivery(t *testing.T) {
	keyfile := filepath.Join(t.TempDir(), "core.key")
	if err := os.WriteFile(keyfile, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	plan := manager.EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30,
		Bindings: []egress.Binding{{Inbound: "qa", Outbound: "qa"}}},
		Profiles: []manager.EgressProfile{{ID: "qa", Config: json.RawMessage(`{"protocol":"blackhole","settings":{}}`)}}}
	document := func(p manager.EgressPlan) *controlplane.EgressDocument {
		data, _ := json.Marshal(p)
		digest := sha256.Sum256(data)
		return &controlplane.EgressDocument{Revision: p.Snapshot.Revision, Digest: hex.EncodeToString(digest[:]), PlanJSON: string(data)}
	}
	var mu sync.Mutex
	state := controlplane.EgressControl{Desired: document(plan)}
	unavailable := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/egress"):
			if unavailable {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			json.NewEncoder(w).Encode(state)
		case strings.HasSuffix(r.URL.Path, "/egress/identity"):
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	client, err := controlplane.New(&controlplane.Config{CoreID: "11111111-1111-4111-8111-111111111111", KeyFile: keyfile, APIHost: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseEgressHealth()
	defer client.CloseEgressPreflight()
	config := &manager.Config{LogConfig: &manager.LogConfig{Level: "none"}}
	m := manager.New(config)
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := syncEgress(client, m, config); err != nil {
		t.Fatal(err)
	}
	dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	before := m.Server
	dispatcher.Egress.RestrictLease(time.Now().Add(-time.Second))
	mu.Lock()
	state.CredentialRuntimeVersion = 1
	mu.Unlock()
	if err := syncEgress(client, m, config); err == nil {
		t.Fatal("credential delivery error was hidden")
	}
	if _, managed, expired := dispatcher.Egress.Lookup("qa"); !managed || expired || m.Server != before {
		t.Fatal("fresh unchanged authorization did not renew without rebuilding core")
	}
	stored, err := egress.LoadState(filepath.Join(filepath.Dir(keyfile), "egress-state.bin"), client.Config.CoreID, client.Key)
	if err != nil || !stored.ExpiresAt.After(time.Now()) {
		t.Fatal("renewal was not durably journaled", err)
	}

	// A new candidate must still wait for its credentials; an unavailable panel
	// must never allow renewal from a cached document alone.
	dispatcher.Egress.RestrictLease(time.Now().Add(-time.Second))
	changed := plan
	changed.Snapshot.Revision = 2
	mu.Lock()
	state.Desired = document(changed)
	mu.Unlock()
	if err := syncEgress(client, m, config); err == nil {
		t.Fatal("new plan ignored failed credential delivery")
	}
	if _, _, expired := dispatcher.Egress.Lookup("qa"); !expired || dispatcher.Egress.Revision() != 1 {
		t.Fatal("changed candidate renewed or replaced live authorization")
	}
	mu.Lock()
	state.Desired = document(plan)
	unavailable = true
	mu.Unlock()
	if err := syncEgress(client, m, config); err == nil {
		t.Fatal("missing panel authorization accepted")
	}
	if _, _, expired := dispatcher.Egress.Lookup("qa"); !expired {
		t.Fatal("cached authorization renewed while panel unavailable")
	}
}

func TestManagedEgressRenewalIsPrioritizedWithoutPollingEveryStage(t *testing.T) {
	now := time.Now()
	config := &manager.Config{}
	if managedEgressRenewalDue(config, now) {
		t.Fatal("unmanaged core scheduled egress renewal")
	}
	config.RestoredEgress = &manager.EgressPlan{}
	config.EgressExpiresAt = now.Add(30 * time.Second)
	if managedEgressRenewalDue(config, now) {
		t.Fatal("fresh authorization triggered redundant polling")
	}
	if !managedEgressRenewalDue(config, now.Add(15*time.Second)) {
		t.Fatal("slow control work can starve live renewal")
	}
	if !managedEgressRenewalDue(config, now.Add(31*time.Second)) {
		t.Fatal("expired authorization cannot recover")
	}
}
