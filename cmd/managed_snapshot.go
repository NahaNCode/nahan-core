package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/api/nahan"
	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/service/controller"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"os"
	"path/filepath"
)

type managedSnapshot struct {
	CoreID   string                 `json:"coreId"`
	Manifest *controlplane.Manifest `json:"manifest"`
	Nodes    []*api.NodeInfo        `json:"nodes"`
}

func decodeManagedSnapshot(data []byte, coreID string) (*managedSnapshot, error) {
	var snapshot managedSnapshot
	if json.Unmarshal(data, &snapshot) != nil || snapshot.CoreID != coreID || snapshot.Manifest == nil || len(snapshot.Nodes) != len(snapshot.Manifest.Nodes) {
		return nil, fmt.Errorf("invalid managed snapshot")
	}
	for _, node := range snapshot.Nodes {
		if node == nil {
			return nil, fmt.Errorf("invalid managed snapshot node")
		}
		// Older snapshots encoded absent RawMessage fields as JSON null. That is
		// not an advanced profile and must continue through the legacy builder.
		if bytes.Equal(bytes.TrimSpace(node.InboundProfile), []byte("null")) {
			node.InboundProfile = nil
		}
		if bytes.Equal(bytes.TrimSpace(node.Header), []byte("null")) {
			node.Header = nil
		}
	}
	return &snapshot, nil
}

func snapshotPath(panel *controlplane.Client) string {
	return filepath.Join(filepath.Dir(panel.Config.KeyFile), "last-good-entry-manifest.json")
}
func saveManagedSnapshot(panel *controlplane.Client, manifest *controlplane.Manifest, nodes []*manager.NodesConfig) error {
	snapshot := managedSnapshot{CoreID: panel.Config.CoreID, Manifest: manifest}
	for _, node := range nodes {
		prepared, ok := node.PreparedAPI.(*nahan.PreparedClient)
		if !ok {
			return fmt.Errorf("snapshot API unavailable")
		}
		snapshot.Nodes = append(snapshot.Nodes, prepared.Node)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	directory := filepath.Dir(snapshotPath(panel))
	file, err := os.CreateTemp(directory, ".last-good-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), snapshotPath(panel)); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func restoreManagedSnapshot(panel *controlplane.Client, template *controller.Config) (*controlplane.Manifest, []*manager.NodesConfig, error) {
	filename := snapshotPath(panel)
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, fmt.Errorf("last good snapshot unavailable")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}
	snapshot, err := decodeManagedSnapshot(data, panel.Config.CoreID)
	if err != nil {
		return nil, nil, err
	}
	nodes := managedNodes(panel, snapshot.Manifest, template)
	for index, node := range nodes {
		if snapshot.Nodes[index].NodeID != node.ApiConfig.NodeID {
			return nil, nil, fmt.Errorf("snapshot node mismatch")
		}
		// Never restore cached subscriber grants: expiry and revocation are checked again.
		client := nahan.New(node.ApiConfig)
		_, _ = client.GetNodeInfo()
		subscriptions, err := client.GetSubscriptionList()
		if err != nil {
			return nil, nil, fmt.Errorf("snapshot services unavailable")
		}
		node.PreparedAPI = &nahan.PreparedClient{APIClient: client, Node: snapshot.Nodes[index], Subscriptions: subscriptions}
	}
	return snapshot.Manifest, nodes, nil
}
