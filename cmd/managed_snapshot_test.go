package cmd

import (
	"encoding/json"
	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/service/controller"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"testing"
)

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
