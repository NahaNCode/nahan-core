package manager

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/infra/conf"
	"testing"
)

func TestTunnelEndpointSupportsProxyProtocolsAndPreservesSecurity(t *testing.T) {
	binding := egress.TunnelBinding{ID: greQAID, Interface: greQAName, LocalCIDR: "10.241.87.1/30", PeerIP: "10.241.87.2"}
	for _, protocol := range []string{"vless", "vmess", "trojan", "shadowsocks"} {
		t.Run(protocol, func(t *testing.T) {
			key := "servers"
			endpoint := map[string]any{"address": "public.example", "port": 443, "method": "aes-128-gcm", "password": "qa-test-credential"}
			if protocol == "vless" || protocol == "vmess" {
				key = "vnext"
				endpoint = map[string]any{"address": "public.example", "port": 443, "users": []any{map[string]any{"id": "11111111-1111-4111-8111-111111111111", "encryption": "none", "security": "auto"}}}
			}
			settings, _ := json.Marshal(map[string]any{key: []any{endpoint}})
			raw := json.RawMessage(settings)
			document := `{"network":"ws","security":"tls","tlsSettings":{"serverName":"tls.example","allowInsecure":false},"wsSettings":{"path":"/proxy","host":"ws.example"},"sockopt":{"tcpKeepAliveIdle":30}}`
			if protocol == "vless" {
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "reality.example", "fingerprint": "chrome", "password": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": "1234"}, "sockopt": map[string]any{"tcpKeepAliveIdle": 30}})
				if err != nil {
					t.Fatal(err)
				}
				document = string(data)
			}
			var stream conf.StreamConfig
			if err := json.Unmarshal([]byte(document), &stream); err != nil {
				t.Fatal(err)
			}
			config := conf.OutboundDetourConfig{Protocol: protocol, Settings: &raw, StreamSetting: &stream}
			beforeSecurity, _ := json.Marshal(stream.REALITYSettings)
			beforeTLS, _ := json.Marshal(stream.TLSSettings)
			beforeWS, _ := json.Marshal(stream.WSSettings)
			if err := bindTunnelEndpoint(&config, binding); err != nil {
				t.Fatal(err)
			}
			if config.StreamSetting != &stream || config.StreamSetting.Security != stream.Security || config.StreamSetting.SocketSettings.TCPKeepAliveIdle != 30 {
				t.Fatal("stream/security options were replaced")
			}
			afterSecurity, _ := json.Marshal(stream.REALITYSettings)
			afterTLS, _ := json.Marshal(stream.TLSSettings)
			afterWS, _ := json.Marshal(stream.WSSettings)
			if string(beforeSecurity) != string(afterSecurity) || string(beforeTLS) != string(afterTLS) || string(beforeWS) != string(afterWS) {
				t.Fatal("TLS/REALITY/WS parameters changed")
			}
			var parsed map[string][]map[string]any
			if err := json.Unmarshal(*config.Settings, &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed[key][0]["address"] != "10.241.87.2" || *config.SendThrough != "10.241.87.1" || stream.SocketSettings.Interface != greQAName {
				t.Fatal("GRE endpoint binding incorrect")
			}
			if _, err := config.Build(); err != nil {
				t.Fatal("pinned Xray rejected protocol configuration", err)
			}
		})
	}
}

func TestTunnelEndpointRejectsOtherDialerAndMultipleTargets(t *testing.T) {
	binding := egress.TunnelBinding{ID: greQAID, Interface: greQAName, LocalCIDR: "10.241.87.1/30", PeerIP: "10.241.87.2"}
	raw := json.RawMessage(`{"vnext":[{"address":"example.com","port":443},{"address":"example.net","port":443}]}`)
	config := conf.OutboundDetourConfig{Protocol: "vless", Settings: &raw}
	if bindTunnelEndpoint(&config, binding) == nil {
		t.Fatal("multiple endpoints accepted for single tunnel")
	}
	raw = json.RawMessage(`{"vnext":[{"address":"example.com","port":443}]}`)
	config.StreamSetting = &conf.StreamConfig{SocketSettings: &conf.SocketConfig{DialerProxy: "bypass-gre"}}
	if bindTunnelEndpoint(&config, binding) == nil {
		t.Fatal("alternate dialer bypass accepted")
	}
	config.StreamSetting = &conf.StreamConfig{Port: 8443}
	if bindTunnelEndpoint(&config, binding) == nil {
		t.Fatal("alternate stream destination accepted")
	}
	for _, transport := range []*conf.SplitHTTPConfig{
		{DownloadSettings: &conf.StreamConfig{}},
		{Extra: json.RawMessage(`{"downloadSettings":{"address":"bypass.example"}}`)},
	} {
		config.StreamSetting = &conf.StreamConfig{XHTTPSettings: transport}
		if bindTunnelEndpoint(&config, binding) == nil {
			t.Fatal("separate XHTTP download stream accepted")
		}
	}
}

func TestTunnelEndpointPreservesImplicitTLSAndWebSocketIdentity(t *testing.T) {
	binding := egress.TunnelBinding{ID: greQAID, Interface: greQAName, LocalCIDR: "10.241.87.1/30", PeerIP: "10.241.87.2"}
	for _, security := range []string{"tls", "TLS", "none"} {
		t.Run(security, func(t *testing.T) {
			raw := json.RawMessage(`{"vnext":[{"address":"proxy.example","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none"}]}]}`)
			stream := &conf.StreamConfig{Security: security, WSSettings: &conf.WebSocketConfig{Path: "/proxy"}}
			config := conf.OutboundDetourConfig{Protocol: "vless", Settings: &raw, StreamSetting: stream}
			if err := bindTunnelEndpoint(&config, binding); err != nil {
				t.Fatal(err)
			}
			if security == "tls" || security == "TLS" {
				if stream.TLSSettings == nil || stream.TLSSettings.ServerName != "proxy.example" || stream.TLSSettings.AllowInsecure {
					t.Fatal("implicit verified TLS identity lost")
				}
			} else if stream.WSSettings.Host != "proxy.example" {
				t.Fatal("implicit WebSocket host lost")
			}
		})
	}
}
