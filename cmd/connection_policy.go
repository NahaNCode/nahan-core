package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/utility/connectionpolicy"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/xtls/xray-core/features/routing"
	"os"
	"path/filepath"
)

func policyPath(c *controlplane.Client) string {
	return filepath.Join(filepath.Dir(c.Config.KeyFile), "connection-policy.json")
}
func restorePolicy(c *controlplane.Client) (connectionpolicy.Snapshot, error) {
	var p connectionpolicy.Snapshot
	data, err := os.ReadFile(policyPath(c))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	var stored struct {
		CoreID string                    `json:"coreId"`
		Policy connectionpolicy.Snapshot `json:"policy"`
	}
	err = json.Unmarshal(data, &stored)
	if err == nil && stored.CoreID != c.Config.CoreID {
		return p, fmt.Errorf("policy belongs to another core")
	}
	p = stored.Policy
	if err == nil {
		err = connectionpolicy.Validate(p)
	}
	return p, err
}
func persistPolicy(c *controlplane.Client, p connectionpolicy.Snapshot) error {
	data, err := json.Marshal(struct {
		CoreID string                    `json:"coreId"`
		Policy connectionpolicy.Snapshot `json:"policy"`
	}{c.Config.CoreID, p})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(policyPath(c)), ".policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), policyPath(c))
}
func syncPolicy(c *controlplane.Client, m *manager.Manager, config *manager.Config) error {
	p, err := c.ConnectionPolicy(context.Background())
	if err != nil {
		return err
	}
	current := config.ConnectionPolicy
	if p.Revision < current.Revision {
		return c.PolicyReceipt(context.Background(), p.Revision, "stale_policy")
	}
	if p.Revision != current.Revision {
		if err = persistPolicy(c, p); err != nil {
			return c.PolicyReceipt(context.Background(), p.Revision, "persistence_failed")
		}
		// The validated snapshot swap does not rebuild handlers or close any sessions.
		d := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
		if err = d.ConnectionPolicy.Replace(p); err != nil {
			return err
		}
		config.ConnectionPolicy = p
	}
	return c.PolicyReceipt(context.Background(), p.Revision, "")
}
