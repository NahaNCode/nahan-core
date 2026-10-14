package manager

import (
	"encoding/json"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/infra/conf"
	"testing"
)

func TestEgressPrincipalReferenceRejectsInlineCustomerCredentials(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		t.Run(kind, func(t *testing.T) {
			principal, err := egress.NewPrincipalCredential(kind, "")
			if err != nil {
				t.Fatal(err)
			}
			key := "vnext"
			if kind == "trojan" {
				key = "servers"
			}
			endpoint := map[string]any{"address": "proxy.example", "port": 443}
			for _, injected := range []string{"users", "password"} {
				endpoint[injected] = nil
				settings, _ := json.Marshal(map[string]any{key: []any{endpoint}})
				raw := json.RawMessage(settings)
				config := conf.OutboundDetourConfig{Protocol: kind, Settings: &raw}
				if bindPrincipalCredential(&config, principal) == nil {
					t.Fatal("inline credential field accepted")
				}
				delete(endpoint, injected)
			}
			settings, _ := json.Marshal(map[string]any{key: []any{endpoint}})
			raw := json.RawMessage(settings)
			config := conf.OutboundDetourConfig{Protocol: kind, Settings: &raw}
			if err = bindPrincipalCredential(&config, principal); err != nil {
				t.Fatal(err)
			}
			if _, err = config.Build(); err != nil {
				t.Fatal("principal outbound rejected by pinned engine", err)
			}
		})
	}
}
