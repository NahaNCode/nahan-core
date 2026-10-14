package egress

import (
	"errors"
	"net"
	"net/netip"
	"strings"
)

type TunnelBinding struct {
	ID        string `json:"id"`
	Interface string `json:"interface"`
	LocalCIDR string `json:"localCIDR"`
	PeerIP    string `json:"peerIP"`
}

func (b TunnelBinding) Addresses() (netip.Prefix, netip.Addr, error) {
	local, e1 := netip.ParsePrefix(b.LocalCIDR)
	peer, e2 := netip.ParseAddr(b.PeerIP)
	if !uuid.MatchString(b.ID) || b.Interface != "nhg"+strings.ReplaceAll(b.ID, "-", "")[:12] || e1 != nil || e2 != nil || !local.Addr().Is4() || local.Bits() != 30 || !local.Addr().IsPrivate() || !peer.Is4() || !local.Contains(peer) || local.Addr() == peer {
		return local, peer, errors.New("invalid managed tunnel binding")
	}
	base := local.Masked().Addr().As4()
	for _, ip := range []netip.Addr{local.Addr(), peer} {
		last := ip.As4()[3] - base[3]
		if last != 1 && last != 2 {
			return local, peer, errors.New("invalid tunnel host address")
		}
	}
	return local, peer, nil
}

// Checks the namespace of the actual core process, not the agent's namespace.
func (b TunnelBinding) VerifyLocal() error {
	local, _, err := b.Addresses()
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByName(b.Interface)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return errors.New("managed tunnel interface unavailable in core namespace")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return errors.New("managed tunnel addresses unavailable")
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix == local {
			return nil
		}
	}
	return errors.New("managed tunnel local address missing in core namespace")
}
