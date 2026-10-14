package nahan

import (
	"encoding/json"
	"errors"
	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"strconv"
)

func (c *APIClient) parseEntryProfile(server *serverConfig) (*api.NodeInfo, error) {
	if c.protocol != "nahan-v1" || c.coreID == "" || c.secretsDir == "" {
		return nil, errors.New("managed profile unavailable")
	}
	resolved, err := entryprofile.Resolve(server.InboundProfile, c.secretsDir, c.coreID)
	if err != nil {
		return nil, errors.New("entry secret resolution failed")
	}
	if !entryprofile.Preflight(resolved).Valid {
		return nil, errors.New("entry build validation failed")
	}
	var p struct {
		Protocol string `json:"protocol"`
		Listen   string `json:"listen"`
		Port     int    `json:"port"`
		Settings struct {
			Flow     string `json:"flow"`
			Method   string `json:"method"`
			Password string `json:"password"`
		} `json:"settings"`
		Stream struct {
			Network  string `json:"network"`
			Method   string `json:"method"`
			Security string `json:"security"`
		} `json:"streamSettings"`
	}
	if json.Unmarshal(resolved, &p) != nil || p.Port < 1 || p.Port > 65535 {
		return nil, errors.New("unsupported managed entry endpoint")
	}
	kind := map[string]string{"vless": "Vless", "vmess": "Vmess", "trojan": "Trojan", "shadowsocks": "Shadowsocks"}[p.Protocol]
	if kind == "" {
		return nil, errors.New("managed service protocol unsupported")
	}
	if server.EntryRole != "" && server.EntryRole != "customer" && server.EntryRole != "exit" && server.EntryRole != "transit" {
		return nil, errors.New("unsupported managed entry role")
	}
	if (server.EntryRole == "transit" || server.EntryRole == "exit") && (p.Protocol != "shadowsocks" || !server.Infrastructure) {
		return nil, errors.New("transit and exit roles require a managed infrastructure listener")
	}
	if server.EntryRole == "customer" && server.Infrastructure {
		return nil, errors.New("infrastructure listener cannot claim customer role")
	}
	network := p.Stream.Network
	if p.Stream.Method != "" {
		network = p.Stream.Method
	}
	if network == "" {
		network = "raw"
	}
	return &api.NodeInfo{Transit: server.EntryRole == "transit", NodeType: kind, NodeID: c.NodeID, Port: strconv.Itoa(p.Port), ListenIP: p.Listen, Address: server.Address, Transport: network, TLSType: p.Stream.Security, CertMode: "none", Flow: p.Settings.Flow, CypherMethod: p.Settings.Method, ServerKey: p.Settings.Password, InboundProfile: resolved}, nil
}

// The node snapshot is pinned to a manifest revision, while service eligibility
// continues to refresh from the panel (expiry, quota and access revocation).
type PreparedClient struct {
	*APIClient
	Node              *api.NodeInfo
	Subscriptions     *[]api.SubscriptionInfo
	nodeRead          bool
	subscriptionsRead bool
}

func (c *PreparedClient) GetNodeInfo() (*api.NodeInfo, error) {
	if c.nodeRead {
		return nil, errors.New(api.NodeNotModified)
	}
	c.nodeRead = true
	return c.Node, nil
}
func (c *PreparedClient) GetSubscriptionList() (*[]api.SubscriptionInfo, error) {
	if !c.subscriptionsRead {
		c.subscriptionsRead = true
		return c.Subscriptions, nil
	}
	list, err := c.APIClient.GetSubscriptionList()
	if err == nil {
		c.Subscriptions = list
	}
	return list, err
}
func (c *PreparedClient) Reset() {
	if list, err := c.APIClient.GetSubscriptionList(); err == nil {
		c.Subscriptions = list
	} else if err.Error() != api.SubscriptionNotModified {
		empty := []api.SubscriptionInfo{}
		c.Subscriptions = &empty
	}
	c.nodeRead = false
	c.subscriptionsRead = false
}
