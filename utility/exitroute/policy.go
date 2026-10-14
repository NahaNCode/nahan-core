// Package exitroute selects an owned destination-side IP without changing the
// server's default route or the IP used to reach its shared listener.
package exitroute

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/NahaNCode/nahan-core/utility/egress"
)

type Rule struct {
	ID       string `json:"id"`
	Mode     string `json:"mode"`
	Inbound  string `json:"inbound"`
	SourceIP string `json:"sourceIP,omitempty"`
	LocalIP  string `json:"localIP,omitempty"`
	ExitIP   string `json:"exitIP"`
	Active   bool   `json:"active"`
}

type Snapshot struct {
	Revision     int64  `json:"revision"`
	LeaseSeconds int    `json:"leaseSeconds"`
	Rules        []Rule `json:"rules"`
}

type Policy struct {
	mu       sync.RWMutex
	registry egress.Registry
	rules    []Rule
}

var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var inbound = regexp.MustCompile(`^(Shadowsocks|Vless|Vmess|Trojan)_[0-9]{1,5}_[0-9]{1,20}$`)

func ipv4(value string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(value)
	return a, err == nil && a.Is4() && a.String() == value && a.IsGlobalUnicast()
}

func Validate(s Snapshot, owned func(netip.Addr) bool) error {
	if s.Revision < 1 || s.LeaseSeconds < 10 || s.LeaseSeconds > 300 || len(s.Rules) > 256 || owned == nil {
		return errors.New("invalid destination exit snapshot")
	}
	ids, selectors := map[string]bool{}, map[string]bool{}
	modes := map[string]string{}
	for _, r := range s.Rules {
		ip, valid := ipv4(r.ExitIP)
		if !uuid.MatchString(r.ID) || ids[r.ID] || !inbound.MatchString(r.Inbound) || !valid || ip.IsPrivate() || (r.Active && !owned(ip)) {
			return errors.New("destination exit IP or identity rejected")
		}
		ids[r.ID] = true
		if previous := modes[r.Inbound]; previous != "" && (previous == "independent" || r.Mode == "independent") {
			return errors.New("independent listener overlaps another exit route")
		}
		modes[r.Inbound] = r.Mode
		switch r.Mode {
		case "independent":
			if r.SourceIP != "" || r.LocalIP != "" {
				return errors.New("independent listener cannot have tunnel selectors")
			}
		case "shared":
			source, sourceOK := ipv4(r.SourceIP)
			local, localOK := ipv4(r.LocalIP)
			if !sourceOK || !localOK || !source.IsPrivate() || !local.IsPrivate() || source == local || (r.Active && !owned(local)) || netip.PrefixFrom(source, 30).Masked() != netip.PrefixFrom(local, 30).Masked() || (source.As4()[3]&3 != 1 && source.As4()[3]&3 != 2) || (local.As4()[3]&3 != 1 && local.As4()[3]&3 != 2) {
				return errors.New("shared exit requires a locally owned tunnel endpoint")
			}
		default:
			return errors.New("unsupported destination exit mode")
		}
		key := r.Inbound + "|" + r.SourceIP + "|" + r.LocalIP
		if selectors[key] {
			return errors.New("shared listener connections cannot distinguish these exit routes")
		}
		selectors[key] = true
	}
	return nil
}

// Apply installs handlers and their complete routing snapshot under one lock.
// A rejected installation leaves selection unchanged; the installer must roll
// back created handlers if Registry.Replace rejects its revision or aliases.
func (p *Policy) Apply(s Snapshot, owned func(netip.Addr) bool, install func(egress.Snapshot, *egress.Registry) error) error {
	if err := Validate(s, owned); err != nil {
		return err
	}
	if install == nil {
		return errors.New("missing destination exit installer")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	bindings := make([]egress.Binding, 0, len(s.Rules))
	for _, rule := range s.Rules {
		bindings = append(bindings, egress.Binding{Inbound: rule.ID, Outbound: rule.ID})
	}
	if err := install(egress.Snapshot{Revision: s.Revision, LeaseSeconds: s.LeaseSeconds, Bindings: bindings}, &p.registry); err != nil {
		return err
	}
	p.rules = append([]Rule(nil), s.Rules...)
	return nil
}

func (p *Policy) Acquire(tag, source, local string) (string, bool, bool, func()) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, rule := range p.rules {
		if rule.Inbound != tag {
			continue
		}
		// Xray's wildcard TCP/UDP listeners report the configured wildcard
		// gateway. A validated /30 pair identifies its sole owned peer endpoint.
		if rule.Mode == "independent" || (rule.SourceIP == source && (rule.LocalIP == local || local == "0.0.0.0" || local == "::")) {
			if !rule.Active {
				return "", true, true, func() {}
			}
			outbound, managed, expired, release := p.registry.Acquire(rule.ID)
			if !managed {
				return "", true, true, release
			}
			return outbound, managed, expired, release
		}
		// A missing local socket identity must not silently select the default IP.
		if rule.SourceIP == source && strings.TrimSpace(local) == "" {
			return "", true, true, func() {}
		}
	}
	return "", false, false, func() {}
}

// Reserve restores only the fail-closed selectors before listeners start.
func (p *Policy) Reserve(s Snapshot) error {
	if err := Validate(s, func(netip.Addr) bool { return true }); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = append([]Rule(nil), s.Rules...)
	return nil
}

func (p *Policy) RestrictLease(until time.Time) { p.registry.RestrictLease(until) }
