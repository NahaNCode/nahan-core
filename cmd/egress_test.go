package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/features/routing"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEgressControlPreparePublishJournalRestartAndStalePlan(t *testing.T) {
	const coreID = "11111111-1111-4111-8111-111111111111"
	keyFile := filepath.Join(t.TempDir(), "core.key")
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	plan := manager.EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []egress.Binding{{EntryID: 1, Inbound: "Vless_443_1", Outbound: "qa"}}}, Profiles: []manager.EgressProfile{{ID: "qa", Config: json.RawMessage(`{"protocol":"blackhole","settings":{}}`)}}}
	document := func(plan manager.EgressPlan) controlplane.EgressDocument {
		data, _ := json.Marshal(plan)
		hash := sha256.Sum256(data)
		return controlplane.EgressDocument{Revision: plan.Snapshot.Revision, Digest: hex.EncodeToString(hash[:]), PlanJSON: string(data)}
	}
	prepared := document(plan)
	var mu sync.Mutex
	state := controlplane.EgressControl{Prepared: &prepared}
	receipts := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(state)
			return
		}
		var receipt map[string]any
		if json.NewDecoder(r.Body).Decode(&receipt) != nil {
			w.WriteHeader(400)
			return
		}
		receipts = append(receipts, receipt)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := controlplane.New(&controlplane.Config{CoreID: coreID, KeyFile: keyFile, APIHost: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseEgressPreflight()
	config := &manager.Config{LogConfig: &manager.LogConfig{Level: "none"}}
	m := manager.New(config)
	if err = m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	if err = syncEgress(client, m, config); err != nil {
		t.Fatal(err)
	}
	if dispatcher.Egress.Revision() != 0 {
		t.Fatal("prepare changed routing")
	}
	deadline := time.Now().Add(time.Second)
	for {
		mu.Lock()
		ready := len(receipts) > 0
		mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("asynchronous preflight receipt missing")
		}
		time.Sleep(time.Millisecond)
		if err = syncEgress(client, m, config); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	if len(receipts) != 1 || receipts[0]["phase"] != "prepared" || receipts[0]["code"] != "" {
		t.Error("preflight receipt missing")
	}
	state = controlplane.EgressControl{Desired: &prepared}
	mu.Unlock()
	if err = syncEgress(client, m, config); err != nil {
		t.Fatal(err)
	}
	if dispatcher.Egress.Revision() != 1 {
		t.Fatal("published plan was not applied")
	}
	before := m.Server
	if err = syncEgress(client, m, config); err != nil || m.Server != before {
		t.Fatal("renewal rebuilt core", err)
	}
	stored, err := egress.LoadState(filepath.Join(filepath.Dir(keyFile), "egress-state.bin"), coreID, client.Key)
	if err != nil {
		t.Fatal(err)
	}
	stored.ExpiresAt = time.Now().Add(-time.Second)
	if err = egress.SaveState(filepath.Join(filepath.Dir(keyFile), "egress-state.bin"), coreID, client.Key, stored); err != nil {
		t.Fatal(err)
	}
	restartedConfig := &manager.Config{LogConfig: &manager.LogConfig{Level: "none"}}
	if err = restoreEgress(client, restartedConfig); err != nil {
		t.Fatal(err)
	}
	restarted := manager.New(restartedConfig)
	if err = restarted.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restoredDispatcher := restarted.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	if _, managed, expired := restoredDispatcher.Egress.Lookup("Vless_8443_1"); !managed || expired {
		t.Fatal("committed route stopped after restart solely because its refresh timestamp passed")
	}
	if stored.RoutePublication != "committed" || !restartedConfig.PersistentEgress {
		t.Fatal("successful route publication was not durably committed")
	}
	stored.RoutePublication = "prepared"
	if err = egress.SaveState(filepath.Join(filepath.Dir(keyFile), "egress-state.bin"), coreID, client.Key, stored); err != nil {
		t.Fatal(err)
	}
	interruptedConfig := &manager.Config{LogConfig: &manager.LogConfig{Level: "none"}}
	if err = restoreEgress(client, interruptedConfig); err != nil {
		t.Fatal(err)
	}
	interrupted := manager.New(interruptedConfig)
	if err = interrupted.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer interrupted.Close()
	if _, managed, blocked := interrupted.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher).Egress.Lookup("Vless_443_1"); !managed || !blocked {
		t.Fatal("uncommitted write-ahead plan became active after restart")
	}
	changed := plan
	changed.Profiles = []manager.EgressProfile{{ID: "qa", Config: json.RawMessage(`{"protocol":"freedom","settings":{}}`)}}
	bad := document(changed)
	mu.Lock()
	state = controlplane.EgressControl{Desired: &bad}
	mu.Unlock()
	if err = syncEgress(client, m, config); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	last := receipts[len(receipts)-1]
	mu.Unlock()
	if last["code"] != "apply_failed" {
		t.Fatal("same revision changed payload accepted", last)
	}
	again, err := egress.LoadState(filepath.Join(filepath.Dir(keyFile), "egress-state.bin"), coreID, client.Key)
	if err != nil || string(again.Plan) != string(stored.Plan) {
		t.Fatal("rejected plan overwrote durable state", err)
	}
}
