package connectionpolicy

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

type Rule struct {
	ID             string   `json:"id"`
	Domains        []string `json:"domains"`
	Action         string   `json:"action"`
	DestinationIPs []string `json:"destinationIps,omitempty"`
	Ports          string   `json:"ports,omitempty"`
	Network        string   `json:"network,omitempty"`
	DomainMatch    string   `json:"domainMatch,omitempty"`
}
type Snapshot struct {
	Revision int64  `json:"revision"`
	Rules    []Rule `json:"rules"`
}
type portRange struct{ first, last uint16 }
type compiledRule struct {
	domains      map[string]bool
	ips          []netip.Prefix
	ports        []portRange
	network      string
	exact, block bool
}
type compiled struct{ rules []compiledRule }
type Policy struct{ current atomic.Pointer[compiled] }

var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func parsePorts(value string) ([]portRange, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > 1000 {
		return nil, fmt.Errorf("invalid policy ports")
	}
	parts := strings.Split(value, ",")
	if len(parts) > 100 {
		return nil, fmt.Errorf("too many ports")
	}
	result := make([]portRange, 0, len(parts))
	for _, part := range parts {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid port range")
		}
		first, err := strconv.ParseUint(bounds[0], 10, 16)
		if err != nil || first == 0 {
			return nil, fmt.Errorf("invalid port")
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.ParseUint(bounds[1], 10, 16)
			if err != nil || last < first {
				return nil, fmt.Errorf("invalid port range")
			}
		}
		result = append(result, portRange{uint16(first), uint16(last)})
	}
	return result, nil
}
func prefix(value string) (netip.Prefix, error) {
	if !strings.Contains(value, "/") {
		a, err := netip.ParseAddr(value)
		if err != nil || a.Is4In6() || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("invalid policy IP")
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(value)
	if err != nil || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("invalid policy CIDR")
	}
	return p.Masked(), nil
}
func build(s Snapshot) (*compiled, error) {
	if s.Revision < 0 || len(s.Rules) > 200 {
		return nil, fmt.Errorf("invalid policy")
	}
	seen := map[string]bool{}
	result := &compiled{}
	for _, r := range s.Rules {
		if r.ID == "" || len(r.ID) > 100 || seen[r.ID] || (r.Action != "allow" && r.Action != "block") || len(r.Domains) > 100 || len(r.DestinationIPs) > 100 {
			return nil, fmt.Errorf("invalid policy rule")
		}
		seen[r.ID] = true
		if (r.Network != "" && r.Network != "any" && r.Network != "tcp" && r.Network != "udp") || (r.DomainMatch != "" && r.DomainMatch != "suffix" && r.DomainMatch != "exact") {
			return nil, fmt.Errorf("invalid policy mode")
		}
		if len(r.Domains) == 0 && len(r.DestinationIPs) == 0 && r.Ports == "" && (r.Network == "" || r.Network == "any") {
			return nil, fmt.Errorf("unconditional policy forbidden")
		}
		c := compiledRule{domains: map[string]bool{}, network: r.Network, exact: r.DomainMatch == "exact", block: r.Action == "block"}
		for _, d := range r.Domains {
			if len(d) > 253 || !domainPattern.MatchString(d) {
				return nil, fmt.Errorf("invalid policy domain")
			}
			c.domains[d] = true
		}
		for _, ip := range r.DestinationIPs {
			p, err := prefix(ip)
			if err != nil {
				return nil, err
			}
			c.ips = append(c.ips, p)
		}
		var err error
		c.ports, err = parsePorts(r.Ports)
		if err != nil {
			return nil, err
		}
		result.rules = append(result.rules, c)
	}
	return result, nil
}
func Validate(s Snapshot) error { _, err := build(s); return err }
func (p *Policy) Replace(s Snapshot) error {
	c, err := build(s)
	if err != nil {
		return err
	}
	p.current.Store(c)
	return nil
}
func (p *Policy) Blocked(domain string) bool { return p.BlockedRequest(domain, nil, 0, "") }

// Lists within a condition are OR; different conditions on a rule are AND.
func (p *Policy) BlockedRequest(domain string, ips []netip.Addr, port uint16, network string) bool {
	s := p.current.Load()
	if s == nil {
		return false
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, r := range s.rules {
		if r.network != "" && r.network != "any" && r.network != network {
			continue
		}
		if len(r.domains) > 0 {
			match := false
			for d := domain; d != ""; {
				if r.domains[d] {
					match = true
					break
				}
				if r.exact {
					break
				}
				dot := strings.IndexByte(d, '.')
				if dot < 0 {
					break
				}
				d = d[dot+1:]
			}
			if !match {
				continue
			}
		}
		if len(r.ports) > 0 {
			match := false
			for _, pr := range r.ports {
				if port >= pr.first && port <= pr.last {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		if len(r.ips) > 0 {
			match := false
			for _, ip := range ips {
				for _, pr := range r.ips {
					if pr.Contains(ip.Unmap()) {
						match = true
						break
					}
				}
			}
			if !match {
				continue
			}
		}
		return r.block
	}
	return false
}
