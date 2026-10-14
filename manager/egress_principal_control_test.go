package manager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

func TestEgressPrincipalControlJobToEncryptedImportToRealOutbound(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		t.Run(kind, func(t *testing.T) {
			targetManager, port, _ := principalFixture(t, kind)
			const transferID = "55555555-5555-4555-8555-555555555555"
			scope := egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 1, ExpiresAt: time.Now().Add(time.Minute).Unix()}
			var mu sync.Mutex
			var public string
			var sealed entryprofile.SealedResult
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.URL.Path {
				case "/api/core/v1/cores/" + principalSource + "/egress/identity":
					if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 64) {
						w.WriteHeader(401)
						return
					}
					var identity struct {
						PublicKey               string `json:"publicKey"`
						PrincipalRuntimeVersion int    `json:"principalRuntimeVersion"`
					}
					if json.NewDecoder(r.Body).Decode(&identity) != nil || identity.PrincipalRuntimeVersion != 1 {
						t.Error("missing principal runtime")
						w.WriteHeader(400)
						return
					}
					public = identity.PublicKey
					w.Write([]byte(`{}`))
				case "/api/core/v1/cores/" + principalTarget + "/jobs":
					if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 64) {
						w.WriteHeader(401)
						return
					}
					json.NewEncoder(w).Encode([]map[string]any{{"id": transferID, "kind": "egress-principal", "payload": PrincipalRequest{Scope: scope, Tag: "qa-principal", Protocol: kind, PublicKey: public}}})
				case "/api/core/v1/cores/" + principalTarget + "/jobs/" + transferID + "/result":
					if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 64) {
						w.WriteHeader(401)
						return
					}
					var result map[string]any
					if json.NewDecoder(r.Body).Decode(&result) != nil || result["valid"] != true || result["code"] != "" {
						t.Error("principal job failed")
						w.WriteHeader(400)
						return
					}
					for _, key := range []string{"password", "credential", "profile", "reference", "publicKey"} {
						if _, ok := result[key]; ok {
							t.Error("principal plaintext metadata returned")
						}
					}
					sealed = entryprofile.SealedResult{Ciphertext: result["ciphertext"].(string), WrappedKey: result["wrappedKey"].(string), Nonce: result["nonce"].(string)}
					w.Write([]byte(`{}`))
				case "/api/core/v1/cores/" + principalSource + "/egress/credentials":
					if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 64) {
						w.WriteHeader(401)
						return
					}
					if sealed.Ciphertext == "" {
						w.Write([]byte(`[]`))
						return
					}
					json.NewEncoder(w).Encode([]egress.CredentialImport{{ID: transferID, Kind: "principal", Scope: scope, Sealed: sealed}})
				default:
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			newClient := func(id, key string) *controlplane.Client {
				filename := filepath.Join(t.TempDir(), "core.key")
				if err := os.WriteFile(filename, []byte(key), 0600); err != nil {
					t.Fatal(err)
				}
				client, err := controlplane.New(&controlplane.Config{CoreID: id, KeyFile: filename, APIHost: server.URL})
				if err != nil {
					t.Fatal(err)
				}
				return client
			}
			source := newClient(principalSource, strings.Repeat("s", 64))
			destination := newClient(principalTarget, strings.Repeat("t", 64))
			binding := egress.PrincipalBinding{TransferID: transferID, RouteID: principalRoute, TargetCoreID: principalTarget, Revision: 1, Protocol: kind}
			config := &Config{LogConfig: &LogConfig{Level: "none"}, ResolveEgressPrincipal: func(b egress.PrincipalBinding) (egress.PrincipalCredential, error) {
				return egress.ReadPrincipal(source.ImportedCredentialDirectory(), principalSource, source.Key, b)
			}}
			sourceManager := New(config)
			if err := sourceManager.StartChecked(); err != nil {
				t.Fatal(err)
			}
			defer sourceManager.Close()
			for client, m := range map[*controlplane.Client]*Manager{source: sourceManager, destination: targetManager} {
				client.PrincipalProvision = func(input json.RawMessage, coreID string) (entryprofile.SealedResult, error) {
					var r PrincipalRequest
					if err := json.Unmarshal(input, &r); err != nil {
						return entryprofile.SealedResult{}, err
					}
					return m.ProvisionEgressPrincipal(coreID, r)
				}
			}
			if err := source.SyncEgressCredentials(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := destination.ProcessJobs(context.Background()); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if err := source.SyncEgressCredentials(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			p, err := egress.ReadPrincipal(source.ImportedCredentialDirectory(), principalSource, source.Key, binding)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(filepath.Join(source.ImportedCredentialDirectory(), transferID+".principal.bin"))
			if (p.ID != "" && strings.Contains(string(raw), p.ID)) || (p.Password != "" && strings.Contains(string(raw), p.Password)) {
				t.Fatal("principal stored in plaintext")
			}
			endpointKey := "vnext"
			if kind == "trojan" {
				endpointKey = "servers"
			}
			outbound, _ := json.Marshal(map[string]any{"protocol": kind, "settings": map[string]any{endpointKey: []any{map[string]any{"address": "127.0.0.1", "port": port}}}})
			plan := EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa-source", Outbound: principalRoute}}}, Profiles: []EgressProfile{{ID: principalRoute, Config: outbound, Principal: &binding}}}
			if err = sourceManager.CheckEgress(plan); err != nil {
				t.Fatal(err)
			}
			if err = sourceManager.ApplyEgress(plan); err != nil {
				t.Fatal(err)
			}
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "qa-source"})
			echo := principalEcho(t)
			conn, err := core.Dial(ctx, sourceManager.Server, echo)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if !principalRoundTrip(conn) {
				t.Fatal("reference-based principal outbound failed")
			}
			if err = targetManager.RevokeEgressPrincipal(principalRoute, principalSource, 1); err != nil {
				t.Fatal(err)
			}
			if principalRoundTrip(conn) {
				t.Fatal("revoked remote principal still authorized")
			}
			t.Log("authenticated control job -> sealed source-only delivery -> encrypted local reference -> actual protocol outbound; scoped revoke")
		})
	}
}
