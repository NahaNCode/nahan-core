package manager

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/exitroute"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
)

func localExitAddresses() (map[netip.Addr]bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	addresses := map[netip.Addr]bool{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		values, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			prefix, err := netip.ParsePrefix(value.String())
			if err == nil && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
				addresses[prefix.Addr()] = true
			}
		}
	}
	return addresses, nil
}

func ExitIPInventory() ([]string, error) {
	addresses, err := localExitAddresses()
	if err != nil {
		return nil, err
	}
	result := []string{}
	for address := range addresses {
		if !address.IsPrivate() {
			result = append(result, address.String())
		}
	}
	sort.Strings(result)
	if len(result) > 64 {
		return nil, errors.New("exit IP inventory capacity exceeded")
	}
	return result, nil
}

func (m *Manager) ApplyExitRoutes(snapshot exitroute.Snapshot) error {
	if m.Server == nil {
		return errors.New("core is not running")
	}
	addresses, err := localExitAddresses()
	if err != nil {
		return errors.New("local exit IP inventory unavailable")
	}
	return m.applyExitRoutes(snapshot, func(address netip.Addr) bool { return addresses[address] })
}

func (m *Manager) RestrictExitRoutes(until time.Time) {
	if m.Server != nil {
		m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher).ExitRoutes.RestrictLease(until)
	}
}

func (m *Manager) applyExitRoutes(snapshot exitroute.Snapshot, owned func(netip.Addr) bool) error {
	if m.Server == nil {
		return errors.New("core is not running")
	}
	inputs := m.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	profiles := make([]EgressProfile, 0, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		if _, err := inputs.GetHandler(context.Background(), rule.Inbound); err != nil {
			return errors.New("exit routing listener unavailable")
		}
		config, err := json.Marshal(map[string]any{"protocol": "freedom", "sendThrough": rule.ExitIP, "settings": map[string]any{"domainStrategy": "ForceIPv4"}})
		if err != nil {
			return err
		}
		profiles = append(profiles, EgressProfile{ID: rule.ID, Config: config})
	}
	dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	return dispatcher.ExitRoutes.Apply(snapshot, owned, func(bindings egress.Snapshot, registry *egress.Registry) error {
		return m.applyEgressRuntime(EgressPlan{Snapshot: bindings, Profiles: profiles}, false, &m.exitEgress, registry)
	})
}
