package manager

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/core"
)

func TestEgressManagedPathProbeVerifiesTLSAndDoesNotChangeCustomerEngine(t *testing.T) {
	key := strings.Repeat("k", 64)
	panel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/core/v1/cores/"+principalSource+"/manifest" || r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"revision":1,"nodes":[]}`))
	}))
	defer panel.Close()
	dir := t.TempDir()
	keyfile, cafile := filepath.Join(dir, "core.key"), filepath.Join(dir, "panel.pem")
	if err := os.WriteFile(keyfile, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cafile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: panel.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := controlplane.New(&controlplane.Config{CoreID: principalSource, KeyFile: keyfile, APIHost: panel.URL, CAFile: cafile})
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, public, err := egress.RecipientIdentity(filepath.Join(dir, "recipient.key"))
	if err != nil {
		t.Fatal(err)
	}
	destination, port, customer := principalFixture(t, "vless")
	original := destination.Server
	scope := egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 1, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	sealed, err := destination.ProvisionEgressPrincipal(principalTarget, PrincipalRequest{Scope: scope, Tag: "qa-principal", Protocol: "vless", PublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	if err := egress.ImportPrincipal(c.ImportedCredentialDirectory(), principalSource, c.Key, rsaKey, egress.CredentialImport{ID: principalTarget, Kind: "principal", Scope: scope, Sealed: sealed}); err != nil {
		t.Fatal(err)
	}
	source := New(&Config{LogConfig: &LogConfig{Level: "none"}, ResolveEgressPrincipal: func(b egress.PrincipalBinding) (egress.PrincipalCredential, error) {
		return egress.ReadPrincipal(c.ImportedCredentialDirectory(), principalSource, c.Key, b)
	}})
	if err := source.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	originalSource := source.Server
	customerClient := principalClient(t, customer, port)
	customerConn, err := core.Dial(context.Background(), customerClient, principalEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer customerConn.Close()
	if !principalRoundTrip(customerConn) {
		t.Fatal("customer fixture failed")
	}
	data, err := json.Marshal(map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port}}}})
	if err != nil {
		t.Fatal(err)
	}
	p := EgressProfile{ID: principalRoute, Config: data, Principal: &egress.PrincipalBinding{TransferID: principalTarget, RouteID: principalRoute, TargetCoreID: principalTarget, Revision: 1, Protocol: "vless"}}
	var probeAddress string
	check := func(ctx context.Context, address, user, password string) error {
		probeAddress = address
		return c.ProbeViaSOCKS(ctx, address, user, password)
	}
	if err := source.ProbeEgressProfile(context.Background(), p, check); err != nil {
		t.Fatal("authenticated HTTPS path probe failed", err)
	}
	if source.Server != originalSource || destination.Server != original || !principalRoundTrip(customerConn) {
		t.Fatal("probe changed a customer-serving engine or stream")
	}
	if conn, err := net.DialTimeout("tcp", probeAddress, 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("probe listener leaked")
	}
	wrongTrust, err := controlplane.New(&controlplane.Config{CoreID: principalSource, KeyFile: keyfile, APIHost: panel.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.ProbeEgressProfile(context.Background(), p, wrongTrust.ProbeViaSOCKS); err == nil {
		t.Fatal("untrusted panel TLS accepted by path probe")
	}
	if !principalRoundTrip(customerConn) {
		t.Fatal("failed probe interrupted customer flow")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := source.ProbeEgressProfile(ctx, p, func(ctx context.Context, _, _, _ string) error { <-ctx.Done(); return ctx.Err() }); err == nil {
		t.Fatal("probe ignored cancellation")
	}
	t.Log(fmt.Sprintf("real encrypted-source principal -> VLESS -> verified HTTPS panel, customer flow retained, private loopback probe %s closed", probeAddress))
}
