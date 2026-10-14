package cmd

import (
	"encoding/json"

	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/utility/routingpolicy"
)

func applyRoutingPolicy(policy *routingpolicy.Policy, m *manager.Manager, config *manager.Config, input json.RawMessage, jobID string) (routingpolicy.Report, error) {
	var request routingpolicy.Request
	// Once started, the live registry is authoritative: restored metadata can
	// retain the old snapshot after the route has been explicitly withdrawn.
	bindings := m.HasManagedEgressBindings()
	if m.Server == nil && config.RestoredEgress != nil {
		bindings = len(config.RestoredEgress.Snapshot.Bindings) > 0
	}
	if json.Unmarshal(input, &request) == nil && !request.Enabled && bindings {
		return policy.Inspect(), routingpolicy.ErrRejected
	}
	return policy.Apply(input, jobID)
}
