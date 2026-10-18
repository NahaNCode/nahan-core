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
	config.ResolveExternalOutbound = func(binding egress.ExternalBinding) (json.RawMessage, error) {
		return egress.ReadExternal(c.ExternalOutboundDirectory(), c.Config.CoreID, c.Key, binding)
	}
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
	if c.RoutingPolicyRefresh != nil {
		c.RoutingPolicyRefresh()
	}
	if c.Config.HasCustomRouting {
		c.CloseEgressHealth()
		c.CloseEgressPreflight()
		return errors.New("routing policy requires approval")
	}
	state, err := c.Egress(context.Background())
	if err != nil {
		return err
	}
	if state.CredentialRuntimeVersion == 1 {
		if err = c.SyncEgressCredentials(context.Background()); err != nil {
			return err
		}
	}
	// Renew/apply the live snapshot before starting any candidate path work.
	if err = applyDesiredEgress(c, m, config, state.Desired); err != nil {
		c.CloseEgressHealth()
		return err
	}
	observePublishedEgress(c, m, state.Desired)
	if state.Prepared != nil {
		var plan manager.EgressPlan
		code := ""
		if json.Unmarshal([]byte(state.Prepared.PlanJSON), &plan) != nil || m.CheckEgress(plan) != nil {
			code = "preflight_failed"
		}
		if code != "" {
			c.CloseEgressPreflight()
			return c.EgressReceipt(context.Background(), "prepared", *state.Prepared, code)
		}
		return c.PreparedReceipt(context.Background(), state.Prepared, func(ctx context.Context) error {
			for _, profile := range plan.Profiles {
				if profile.Principal != nil || profile.Secret != nil || profile.External != nil {
					if err := m.ProbeEgressProfile(ctx, profile, c.ProbeViaSOCKS); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
	return c.PreparedReceipt(context.Background(), nil, nil)
}

func observePublishedEgress(c *controlplane.Client, m *manager.Manager, document *controlplane.EgressDocument) {
	if document == nil {
		c.CloseEgressHealth()
		return
	}
	var plan manager.EgressPlan
	if document.Validate() != nil || json.Unmarshal([]byte(document.PlanJSON), &plan) != nil {
		c.CloseEgressHealth()
		return
	}
	// Test only profiles actually bound to live entries, sharing one result per profile.
	bound := map[string]bool{}
	for _, b := range plan.Snapshot.Bindings {
		bound[b.Outbound] = true
	}
	c.ObserveEgress(document, func(ctx context.Context) []controlplane.EgressHealthResult {
		results := make([]controlplane.EgressHealthResult, 0)
		profiles := make([]manager.EgressProfile, 0)
		for _, profile := range plan.Profiles {
			if bound[profile.ID] && (profile.Principal != nil || profile.Secret != nil || profile.External != nil) {
				profiles = append(profiles, profile)
			}
		}
		for _, index := range c.EgressHealthBatch(len(profiles), 4) {
			profile := profiles[index]
			if ctx.Err() != nil {
				break
			}
			if !bound[profile.ID] || (profile.Principal == nil && profile.Secret == nil && profile.External == nil) {
				continue
			}
			var latency int64
			err := m.ProbeEgressProfile(ctx, profile, func(ctx context.Context, address, user, password string) error {
				start := time.Now()
				err := c.ProbeViaSOCKS(ctx, address, user, password)
				latency = time.Since(start).Milliseconds()
				return err
			})
			results = append(results, controlplane.EgressHealthResult{ProfileID: profile.ID, Alive: err == nil, LatencyMS: latency, CheckedAt: time.Now().UTC()})
		}
		return results
	})
}

func applyDesiredEgress(c *controlplane.Client, m *manager.Manager, config *manager.Config, desired *controlplane.EgressDocument) error {
	if desired == nil {
		return nil
	}
	document := *desired
	var plan manager.EgressPlan
	var err error
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
