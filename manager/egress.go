package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
)

type EgressProfile struct {
	External  *egress.ExternalBinding   `json:"external,omitempty"`
	Principal *egress.PrincipalBinding  `json:"principal,omitempty"`
	ID        string                    `json:"id"`
	Config    json.RawMessage           `json:"config,omitempty"`
	Tunnel    *egress.TunnelBinding     `json:"tunnel,omitempty"`
	Secret    *egress.CredentialBinding `json:"secret,omitempty"`
}
type EgressPlan struct {
	Snapshot egress.Snapshot `json:"snapshot"`
	Profiles []EgressProfile `json:"profiles"`
}
type egressRuntime struct {
	sync.Mutex
	server *core.Instance
	tags   map[string]bool
}

// RestrictManagedEgress blocks scoped bindings without changing legacy routing.
func (m *Manager) RestrictManagedEgress(expires time.Time) {
	m.egress.Lock()
	defer m.egress.Unlock()
	if m.Server != nil {
		m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher).Egress.RestrictLease(expires)
	}
}

func (m *Manager) HasManagedEgressBindings() bool {
	m.egress.Lock()
	defer m.egress.Unlock()
	return m.Server != nil && m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher).Egress.HasBindings()
}

// Config hashes provide immutable handler identities. Retired handlers remain
// alive for existing streams; bounded retention prevents unbounded churn.
func (m *Manager) ApplyEgress(plan EgressPlan) error {
	return m.applyEgress(plan, false)
}

func (m *Manager) CheckEgress(plan EgressPlan) error {
	return m.applyEgress(plan, true)
}

func (m *Manager) applyEgress(plan EgressPlan, checkOnly bool) error {
	m.egress.Lock()
	defer m.egress.Unlock()
	if m.Server == nil {
		return errors.New("core is not running")
	}
	if m.egress.server != m.Server {
		m.egress.server, m.egress.tags = m.Server, make(map[string]bool)
	}
	if len(plan.Profiles) > 256 {
		return errors.New("too many egress profiles")
	}
	obm := m.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	aliases := map[string]string{}
	configs := map[string]*core.OutboundHandlerConfig{}
	for _, p := range plan.Profiles {
		if p.External != nil {
			if len(p.Config) > 0 || p.Principal != nil || p.Secret != nil || p.Tunnel != nil || m.managerConfig.ResolveExternalOutbound == nil {
				return errors.New("invalid external profile scope")
			}
			resolved, err := m.managerConfig.ResolveExternalOutbound(*p.External)
			if err != nil {
				return errors.New("external outbound unavailable")
			}
			p.Config = resolved
		}
		if p.ID == "" || len(p.ID) > 128 || len(p.Config) > 65536 {
			return errors.New("invalid egress profile")
		}
		if _, exists := aliases[p.ID]; exists {
			return errors.New("duplicate egress profile")
		}
		var config conf.OutboundDetourConfig
		if json.Unmarshal(p.Config, &config) != nil || !supportedEgressProtocol(config.Protocol) {
			return errors.New("unsupported egress configuration")
		}
		// Reject chaining to arbitrary tags and caller-controlled handler identity.
		if config.Tag != "" || config.ProxySettings != nil {
			return errors.New("egress handler identity is managed")
		}
		if p.Principal != nil {
			if p.Secret != nil || p.Principal.RouteID != p.ID || p.Principal.Protocol != config.Protocol || m.managerConfig.ResolveEgressPrincipal == nil {
				return errors.New("managed principal scope or runtime unavailable")
			}
			principal, err := m.managerConfig.ResolveEgressPrincipal(*p.Principal)
			if err != nil || principal.Protocol != config.Protocol || principal.Validate() != nil {
				return errors.New("imported principal unavailable")
			}
			if err = bindPrincipalCredential(&config, principal); err != nil {
				return err
			}
		}
		if p.Secret != nil {
			if config.Protocol != "shadowsocks" || m.managerConfig.ResolveEgressCredential == nil {
				return errors.New("SS credential runtime unavailable")
			}
			var settings struct {
				Servers []map[string]any `json:"servers"`
			}
			if config.Settings == nil || json.Unmarshal(*config.Settings, &settings) != nil || len(settings.Servers) != 1 || settings.Servers[0]["password"] != nil {
				return errors.New("managed SS requires a local credential reference")
			}
			secret, err := m.managerConfig.ResolveEgressCredential(*p.Secret)
			if err != nil {
				return errors.New("imported SS credential unavailable")
			}
			if settings.Servers[0]["method"] != secret.Method || p.Secret.Method != secret.Method {
				return errors.New("imported SS cipher mismatch")
			}
			settings.Servers[0]["password"] = secret.Password
			data, _ := json.Marshal(settings)
			raw := json.RawMessage(data)
			config.Settings = &raw
		}
		if p.Tunnel != nil {
			if err := p.Tunnel.VerifyLocal(); err != nil {
				return err
			}
			if err := bindTunnelEndpoint(&config, *p.Tunnel); err != nil {
				return err
			}
		}
		canonical, err := json.Marshal(config)
		if err != nil {
			return errors.New("invalid egress configuration")
		}
		hash := sha256.Sum256(canonical)
		tag := "nahan-egress-" + hex.EncodeToString(hash[:])
		config.Tag = tag
		built, err := config.Build()
		if err != nil {
			return errors.New("egress configuration build failed")
		}
		aliases[p.ID], configs[tag] = tag, built
	}
	snapshot := plan.Snapshot
	snapshot.Bindings = append([]egress.Binding(nil), snapshot.Bindings...)
	for i, b := range snapshot.Bindings {
		if tag, exists := aliases[b.Outbound]; exists {
			snapshot.Bindings[i].Outbound = tag
		} else if strings.HasPrefix(b.Outbound, "nahan-egress-") {
			return errors.New("unowned managed outbound reference")
		}
	}
	if _, _, err := egress.Canonical(snapshot); err != nil {
		return err
	}
	if err := dispatcher.Egress.Validate(snapshot); err != nil {
		return err
	}
	for _, binding := range snapshot.Bindings {
		if configs[binding.Outbound] == nil && obm.GetHandler(binding.Outbound) == nil {
			return errors.New("egress outbound unavailable")
		}
	}
	if checkOnly {
		return nil
	}
	// Never retire a handler selected by the candidate or held by a live stream.
	for tag := range m.egress.tags {
		if configs[tag] == nil && dispatcher.Egress.CanRetire(tag) {
			if obm.RemoveHandler(context.Background(), tag) == nil {
				delete(m.egress.tags, tag)
			}
		}
	}
	newCount := 0
	for tag := range configs {
		if !m.egress.tags[tag] {
			newCount++
		}
	}
	if len(m.egress.tags)+newCount > 512 {
		return errors.New("egress drain capacity reached")
	}
	created := []string{}
	rollback := func() {
		for _, tag := range created {
			_ = obm.RemoveHandler(context.Background(), tag)
		}
	}
	for tag, config := range configs {
		if m.egress.tags[tag] {
			continue
		}
		if obm.GetHandler(tag) != nil {
			rollback()
			return errors.New("egress handler collision")
		}
		if err := core.AddOutboundHandler(m.Server, config); err != nil {
			rollback()
			return errors.New("egress staging failed")
		}
		created = append(created, tag)
	}
	if err := dispatcher.Egress.Replace(snapshot, func(tag string) bool { return obm.GetHandler(tag) != nil }); err != nil {
		rollback()
		return err
	}
	for _, tag := range created {
		m.egress.tags[tag] = true
	}
	for tag := range m.egress.tags {
		if configs[tag] == nil && dispatcher.Egress.CanRetire(tag) {
			if obm.RemoveHandler(context.Background(), tag) == nil {
				delete(m.egress.tags, tag)
			}
		}
	}
	return nil
}

func bindPrincipalCredential(config *conf.OutboundDetourConfig, principal egress.PrincipalCredential) error {
	if principal.Validate() != nil || config.Protocol != principal.Protocol {
		return errors.New("principal protocol mismatch")
	}
	key := "vnext"
	if principal.Protocol == "trojan" {
		key = "servers"
	}
	var settings map[string]json.RawMessage
	if config.Settings == nil || json.Unmarshal(*config.Settings, &settings) != nil {
		return errors.New("invalid managed principal settings")
	}
	var endpoints []map[string]any
	if json.Unmarshal(settings[key], &endpoints) != nil || len(endpoints) != 1 {
		return errors.New("managed principal requires one destination")
	}
	if _, exists := endpoints[0]["users"]; exists {
		return errors.New("inline principal identity is forbidden")
	}
	if _, exists := endpoints[0]["password"]; exists {
		return errors.New("inline principal password is forbidden")
	}
	if principal.Protocol == "trojan" {
		endpoints[0]["password"] = principal.Password
	} else {
		user := map[string]any{"id": principal.ID}
		if principal.Protocol == "vless" {
			user["encryption"], user["flow"] = "none", principal.Flow
		} else {
			user["security"] = "auto"
		}
		endpoints[0]["users"] = []any{user}
	}
	data, _ := json.Marshal(endpoints)
	settings[key] = data
	data, _ = json.Marshal(settings)
	raw := json.RawMessage(data)
	config.Settings = &raw
	return nil
}

func supportedEgressProtocol(protocol string) bool {
	return protocol == "freedom" || protocol == "blackhole" || protocol == "shadowsocks" || protocol == "vless" || protocol == "vmess" || protocol == "trojan"
}

// Transport placement is independent of protocol and its TLS/REALITY settings.
func bindTunnelEndpoint(config *conf.OutboundDetourConfig, binding egress.TunnelBinding) error {
	local, peer, err := binding.Addresses()
	if err != nil {
		return err
	}
	if config.ProxySettings != nil || (config.StreamSetting != nil && config.StreamSetting.SocketSettings != nil && config.StreamSetting.SocketSettings.DialerProxy != "") {
		return errors.New("managed tunnel cannot use another dialer proxy")
	}
	if config.StreamSetting != nil && (config.StreamSetting.Address != nil || config.StreamSetting.Port != 0) {
		return errors.New("managed tunnel cannot override the stream destination")
	}
	if config.StreamSetting != nil {
		for _, transport := range []*conf.SplitHTTPConfig{config.StreamSetting.XHTTPSettings, config.StreamSetting.SplitHTTPSettings} {
			if transport == nil {
				continue
			}
			if transport.DownloadSettings != nil {
				return errors.New("managed tunnel cannot use a separate download stream")
			}
			if transport.Extra != nil {
				var extra conf.SplitHTTPConfig
				if json.Unmarshal(transport.Extra, &extra) != nil || extra.DownloadSettings != nil {
					return errors.New("managed tunnel cannot use invalid or separate download settings")
				}
			}
		}
	}
	endpointKey := ""
	switch config.Protocol {
	case "vless", "vmess":
		endpointKey = "vnext"
	case "trojan", "shadowsocks":
		endpointKey = "servers"
	default:
		return errors.New("protocol cannot use managed tunnel")
	}
	var settings map[string]json.RawMessage
	if config.Settings == nil || json.Unmarshal(*config.Settings, &settings) != nil {
		return errors.New("invalid managed destination settings")
	}
	var endpoints []map[string]any
	if json.Unmarshal(settings[endpointKey], &endpoints) != nil || len(endpoints) != 1 {
		return errors.New("managed tunnel requires exactly one destination")
	}
	original, ok := endpoints[0]["address"].(string)
	if !ok || original == "" {
		return errors.New("managed tunnel requires a destination address")
	}
	if config.StreamSetting == nil {
		config.StreamSetting = &conf.StreamConfig{}
	}
	stream := config.StreamSetting
	security := strings.ToLower(stream.Security)
	// Preserve implicit certificate identity when the dial address becomes an inner IP.
	if security == "tls" {
		if stream.TLSSettings == nil {
			stream.TLSSettings = &conf.TLSConfig{}
		}
		if stream.TLSSettings.ServerName == "" {
			stream.TLSSettings.ServerName = original
		}
	}
	if stream.WSSettings != nil && stream.WSSettings.Host == "" && security != "tls" && security != "reality" {
		hasHost := false
		for name := range stream.WSSettings.Headers {
			if strings.EqualFold(name, "host") {
				hasHost = true
			}
		}
		if !hasHost {
			stream.WSSettings.Host = original
		}
	}
	endpoints[0]["address"] = peer.String()
	data, _ := json.Marshal(endpoints)
	settings[endpointKey] = data
	data, _ = json.Marshal(settings)
	raw := json.RawMessage(data)
	config.Settings = &raw
	ip := local.Addr().String()
	config.SendThrough = &ip
	if config.StreamSetting.SocketSettings == nil {
		config.StreamSetting.SocketSettings = &conf.SocketConfig{}
	}
	config.StreamSetting.SocketSettings.Interface = binding.Interface
	return nil
}
