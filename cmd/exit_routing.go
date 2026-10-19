package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/exitroute"
)

func exitStatePath(c *controlplane.Client) string {
	return filepath.Join(filepath.Dir(c.Config.KeyFile), "destination-exit-state.bin")
}

func restoreExitRouting(c *controlplane.Client, config *manager.Config) error {
	state, err := egress.LoadState(exitStatePath(c), c.Config.CoreID, c.Key)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var snapshot exitroute.Snapshot
	if json.Unmarshal(state.Plan, &snapshot) != nil {
		return errors.New("invalid destination exit restoration")
	}
	config.RestoredExitRoutes = &snapshot
	config.ExitRoutesExpiresAt = state.ExpiresAt
	config.PersistentExitRoutes = state.RoutePublication == "committed"
	if state.RoutePublication != "" && state.RoutePublication != "committed" {
		config.ExitRoutesExpiresAt = time.Unix(1, 0)
	}
	return nil
}

func syncExitRouting(c *controlplane.Client, m *manager.Manager, config *manager.Config) error {
	if c.Config.HasCustomRouting {
		m.RestrictExitRoutes(time.Now().Add(-time.Second))
		return errors.New("destination exit requires routing consent")
	}
	ips, err := manager.ExitIPInventory()
	if err != nil {
		return err
	}
	document, err := c.ExitRouting(context.Background(), ips)
	if err != nil {
		return err
	}
	var snapshot exitroute.Snapshot
	if json.Unmarshal([]byte(document.PlanJSON), &snapshot) != nil || snapshot.Revision != document.Revision {
		return errors.New("invalid destination exit document")
	}
	if err = m.ApplyExitRoutes(snapshot); err != nil {
		_ = c.ExitRoutingReceipt(context.Background(), document, "exit_apply_failed")
		return err
	}
	deadline := time.Now().Add(time.Duration(snapshot.LeaseSeconds) * time.Second)
	if err = egress.SaveState(exitStatePath(c), c.Config.CoreID, c.Key, egress.State{CoreID: c.Config.CoreID, ExpiresAt: deadline, Plan: json.RawMessage(document.PlanJSON), RoutePublication: "committed"}); err != nil {
		m.RestrictExitRoutes(time.Now().Add(-time.Second))
		_ = c.ExitRoutingReceipt(context.Background(), document, "exit_persistence_failed")
		return err
	}
	config.RestoredExitRoutes = &snapshot
	config.ExitRoutesExpiresAt = deadline
	config.PersistentExitRoutes = true
	return c.ExitRoutingReceipt(context.Background(), document, "")
}
