package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/features/routing"
	"os"
	"path/filepath"
	"time"
)

func restoreEgress(c *controlplane.Client, config *manager.Config) error {
	config.ResolveEgressPrincipal = func(binding egress.PrincipalBinding) (egress.PrincipalCredential, error) {
		return egress.ReadPrincipal(c.ImportedCredentialDirectory(), c.Config.CoreID, c.Key, binding)
	}
	config.ResolveEgressCredential = func(binding egress.CredentialBinding) (egress.SSCredential, error) {
		return egress.ReadCredential(c.ImportedCredentialDirectory(), c.Config.CoreID, c.Key, binding)
	}
	state, err := egress.LoadState(filepath.Join(filepath.Dir(c.Config.KeyFile), "egress-state.bin"), c.Config.CoreID, c.Key)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var plan manager.EgressPlan
	if err = json.Unmarshal(state.Plan, &plan); err != nil {
		return err
	}
	if _, _, err = egress.Canonical(plan.Snapshot); err != nil {
		return err
	}
	config.RestoredEgress = &plan
	config.EgressExpiresAt = state.ExpiresAt
	return nil
}

func syncEgress(c *controlplane.Client, m *manager.Manager, config *manager.Config) error {
	state, err := c.Egress(context.Background())
	if err != nil {
		return err
	}
	if state.CredentialRuntimeVersion == 1 {
		if err = c.SyncEgressCredentials(context.Background()); err != nil {
			return err
		}
	}
	if state.Prepared != nil {
		var plan manager.EgressPlan
		code := ""
		if json.Unmarshal([]byte(state.Prepared.PlanJSON), &plan) != nil || m.CheckEgress(plan) != nil {
			code = "preflight_failed"
		}
		if err = c.EgressReceipt(context.Background(), "prepared", *state.Prepared, code); err != nil {
			return err
		}
	}
	if state.Desired == nil {
		return nil
	}
	document := *state.Desired
	var plan manager.EgressPlan
	if json.Unmarshal([]byte(document.PlanJSON), &plan) != nil {
		return c.EgressReceipt(context.Background(), "applied", document, "apply_failed")
	}
	if config.RestoredEgress != nil && plan.Snapshot.Revision < config.RestoredEgress.Snapshot.Revision {
		return c.EgressReceipt(context.Background(), "applied", document, "stale_plan")
	}
	if err = m.CheckEgress(plan); err != nil {
		return c.EgressReceipt(context.Background(), "applied", document, "apply_failed")
	}
	expires := time.Now().Add(time.Duration(plan.Snapshot.LeaseSeconds) * time.Second)
	path := filepath.Join(filepath.Dir(c.Config.KeyFile), "egress-state.bin")
	// Write-ahead persistence: crash recovery must never restore an unmanaged
	// direct path for an inbound whose managed route was already published.
	if err = egress.SaveState(path, c.Config.CoreID, c.Key, egress.State{CoreID: c.Config.CoreID, ExpiresAt: expires, Plan: []byte(document.PlanJSON)}); err != nil {
		return c.EgressReceipt(context.Background(), "applied", document, "persistence_failed")
	}
	if err = m.ApplyEgress(plan); err != nil {
		// The journaled candidate is blocked, not active, after a failed apply.
		blocked := plan.Snapshot
		d := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
		_ = d.Egress.Replace(blocked, func(string) bool { return true })
		d.Egress.RestrictLease(time.Now().Add(-time.Second))
		return c.EgressReceipt(context.Background(), "applied", document, "apply_failed")
	}
	config.RestoredEgress = &plan
	config.EgressExpiresAt = expires
	return c.EgressReceipt(context.Background(), "applied", document, "")
}
