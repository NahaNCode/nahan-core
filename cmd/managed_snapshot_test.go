package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/service/controller"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedSnapshotStartsWhenServerDocumentIsInvalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/subscriptions") {
			w.Write([]byte(`{"subscriptions":[],"leaseSeconds":120,"authorizationRevision":1}`))
		} else if strings.HasSuffix(r.URL.Path, "/server") {
			w.Write([]byte(`{}`))
		} else {
			w.Write([]byte(`{"ret":1}`))
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	key := filepath.Join(dir, "core.key")
	if err := os.WriteFile(key, []byte(strings.Repeat("a", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	panel, err := controlplane.New(&controlplane.Config{APIHost: server.URL, CoreID: "11111111-1111-4111-8111-111111111111", KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	manifest := &controlplane.Manifest{Revision: 1}
	data := `{"revision":1,"nodes":[{"id":1}]}`
	if err = json.Unmarshal([]byte(data), manifest); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	profile := json.RawMessage(fmt.Sprintf(`{"protocol":"vless","listen":"127.0.0.1","port":%d,"settings":{"decryption":"none"},"streamSettings":{"network":"raw","security":"none"}}`, port))
	snapshot := managedSnapshot{CoreID: panel.Config.CoreID, Manifest: manifest, Nodes: []*api.NodeInfo{{NodeID: 1, NodeType: "Vless", Port: fmt.Sprint(port), ListenIP: "127.0.0.1", InboundProfile: profile}}, Rules: [][]snapshotRule{{}}}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(snapshotPath(panel), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	_, nodes, err := restoreManagedSnapshot(panel, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := manager.New(&manager.Config{LogConfig: &manager.LogConfig{Level: "none"}, NodesConfig: nodes})
	if err = m.StartChecked(); err != nil {
		t.Fatal("restored engine failed to start", err)
	}
	m.Close()
}

func TestSnapshotRulesRetainEnforcementAndRejectIncompleteState(t *testing.T) {
	snapshot := &managedSnapshot{Nodes: []*api.NodeInfo{{NodeID: 1}}, Rules: [][]snapshotRule{{{ID: 7, Pattern: "blocked[.]example"}}}}
	rules, err := restoredSnapshotRules(snapshot, 0)
	if err != nil || len(*rules) != 1 || (*rules)[0].ID != 7 || !(*rules)[0].Pattern.MatchString("blocked.example") {
		t.Fatal("snapshot lost enforcement rule", err)
	}
	snapshot.Rules = [][]snapshotRule{{}}
	if rules, err = restoredSnapshotRules(snapshot, 0); err != nil || len(*rules) != 0 {
		t.Fatal("explicit empty rule set rejected", err)
	}
	snapshot.Rules = nil
	if _, err = restoredSnapshotRules(snapshot, 0); err == nil {
		t.Fatal("missing legacy rules treated as empty")
	}
	snapshot.Rules = [][]snapshotRule{{{ID: 7, Pattern: "["}}}
	if _, err = restoredSnapshotRules(snapshot, 0); err == nil {
		t.Fatal("invalid snapshot regex accepted")
	}
}

func TestSnapshotLegacyNullProfileRestoresLegacyInbound(t *testing.T) {
	var manifest controlplane.Manifest
	if err := json.Unmarshal([]byte(`{"revision":1,"nodes":[{"id":1}]}`), &manifest); err != nil {
		t.Fatal(err)
	}
	node := &api.NodeInfo{NodeID: 1, NodeType: "Vless", ListenIP: "127.0.0.1", Port: "11243", Transport: "raw", InboundProfile: json.RawMessage(`null`), Header: json.RawMessage(`null`)}
	data, err := json.Marshal(managedSnapshot{CoreID: "test", Manifest: &manifest, Nodes: []*api.NodeInfo{node}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := decodeManagedSnapshot(data, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Nodes[0].InboundProfile) != 0 {
		t.Fatal("legacy null treated as advanced profile")
	}
	if len(snapshot.Nodes[0].Header) != 0 {
		t.Fatal("legacy null treated as TCP header")
	}
	if _, err = controller.InboundBuilder(&controller.Config{}, snapshot.Nodes[0], "restore"); err != nil {
		t.Fatalf("legacy restore build: %v", err)
	}
}
func TestSnapshotAdvancedProfileRetainedAndInvalidIdentityRejected(t *testing.T) {
	var manifest controlplane.Manifest
	_ = json.Unmarshal([]byte(`{"revision":1,"nodes":[{"id":1}]}`), &manifest)
	profile := json.RawMessage(`{"protocol":"vless","listen":"127.0.0.1","port":11243,"settings":{"decryption":"none"},"streamSettings":{"network":"raw","security":"none"}}`)
	data, _ := json.Marshal(managedSnapshot{CoreID: "test", Manifest: &manifest, Nodes: []*api.NodeInfo{{NodeID: 1, InboundProfile: profile}}})
	snapshot, err := decodeManagedSnapshot(data, "test")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Nodes[0].InboundProfile) != string(profile) {
		t.Fatal("advanced profile lost")
	}
	if _, err = controller.InboundBuilder(&controller.Config{}, snapshot.Nodes[0], "restore"); err != nil {
		t.Fatal(err)
	}
	if _, err = decodeManagedSnapshot(data, "other"); err == nil {
		t.Fatal("cross-core snapshot accepted")
	}
	bad, _ := json.Marshal(managedSnapshot{CoreID: "test", Manifest: &manifest, Nodes: []*api.NodeInfo{nil}})
	if _, err = decodeManagedSnapshot(bad, "test"); err == nil {
		t.Fatal("null node accepted")
	}
}
