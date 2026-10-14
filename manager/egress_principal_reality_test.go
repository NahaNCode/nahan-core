package manager

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/utility/egress"
	realityruntime "github.com/xtls/reality"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	xproxy "golang.org/x/net/proxy"
)

func TestEgressPrincipalRealVlessRealityVisionHandshakeAndWrongKeyRejection(t *testing.T) {
	if os.Getenv("NAHAN_REALITY_PRINCIPAL_QA_CHILD") == "1" {
		realityPrincipalAcceptance(t)
		return
	}
	// Protocol acceptance has a fresh engine process, independent of other fixtures.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestEgressPrincipalRealVlessRealityVisionHandshakeAndWrongKeyRejection$", "-test.v", "-test.timeout=30s")
	command.Env = append(os.Environ(), "NAHAN_REALITY_PRINCIPAL_QA_CHILD=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated REALITY principal acceptance failed: %v\n%s", err, output)
	}
	t.Log("isolated process: real physical TCP inbound -> independent principal -> VLESS/REALITY/Vision -> TCP echo; wrong key rejected; existing stream retained")
}

func realityPrincipalAcceptance(t *testing.T) {
	t.Helper()
	camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("QA TLS target")) }))
	camouflage.EnableHTTP2 = true
	camouflage.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	camouflage.StartTLS()
	defer camouflage.Close()
	roots := x509.NewCertPool()
	roots.AddCert(camouflage.Certificate())
	ready, err := tls.Dial("tcp", camouflage.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "example.com", CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal("TLS fixture readiness failed", err)
	}
	ready.Close()
	realityKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stream := map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"target": camouflage.Listener.Addr().String(), "serverNames": []string{"example.com"}, "privateKey": base64.RawURLEncoding.EncodeToString(realityKey.Bytes()), "shortIds": []string{"1234"}}}
	destination, port, _ := principalFixtureWithStream(t, "vless", stream)
	// REALITY probes the target asynchronously; a cold handshake otherwise polls
	// this profile every five seconds after TLS verification has already succeeded.
	profileDeadline := time.Now().Add(10 * time.Second)
	for {
		ready := true
		for _, alpn := range []int{0, 1, 2} {
			value, ok := realityruntime.GlobalPostHandshakeRecordsLens.Load(fmt.Sprintf("%s example.com %d", camouflage.Listener.Addr(), alpn))
			if _, typed := value.([]int); !ok || !typed {
				ready = false
				break
			}
		}
		if ready {
			break
		}
		if time.Now().After(profileDeadline) {
			t.Fatal("REALITY target profile was not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	scope := egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 1, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	r := PrincipalRequest{Scope: scope, Tag: "qa-principal", Protocol: "vless", Flow: "xtls-rprx-vision", PublicKey: base64.StdEncoding.EncodeToString(public)}
	sealed, err := destination.ProvisionEgressPrincipal(principalTarget, r)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	localKey := strings.Repeat("k", 40)
	envelope := egress.CredentialImport{ID: principalTarget, Kind: "principal", Scope: scope, Sealed: sealed}
	if err = egress.ImportPrincipal(directory, principalSource, localKey, key, envelope); err != nil {
		t.Fatal(err)
	}
	binding := egress.PrincipalBinding{TransferID: principalTarget, RouteID: principalRoute, TargetCoreID: principalTarget, Revision: 1, Protocol: "vless"}
	source := New(&Config{LogConfig: &LogConfig{Level: "none"}, ResolveEgressPrincipal: func(b egress.PrincipalBinding) (egress.PrincipalCredential, error) {
		return egress.ReadPrincipal(directory, principalSource, localKey, b)
	}})
	if err = source.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	applicationAddress := reserved.Addr().String()
	applicationPort := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	applicationProfile := []byte(fmt.Sprintf(`{"protocol":"socks","tag":"qa-source","listen":"127.0.0.1","port":%d,"settings":{"auth":"noauth","udp":false}}`, applicationPort))
	var applicationConfig conf.InboundDetourConfig
	if err = json.Unmarshal(applicationProfile, &applicationConfig); err != nil {
		t.Fatal(err)
	}
	applicationInbound, err := applicationConfig.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err = core.AddInboundHandler(source.Server, applicationInbound); err != nil {
		t.Fatal(err)
	}
	dialer, err := xproxy.SOCKS5("tcp", applicationAddress, nil, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	makePlan := func(revision int64, password string) EgressPlan {
		config, _ := json.Marshal(map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port}}}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "example.com", "fingerprint": "chrome", "password": password, "shortId": "1234"}}})
		return EgressPlan{Snapshot: egress.Snapshot{Revision: revision, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa-source", Outbound: principalRoute}}}, Profiles: []EgressProfile{{ID: principalRoute, Config: config, Principal: &binding}}}
	}
	if err = source.ApplyEgress(makePlan(1, base64.RawURLEncoding.EncodeToString(realityKey.PublicKey().Bytes()))); err != nil {
		t.Fatal(err)
	}
	echo := principalEcho(t)
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", echo.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !principalRoundTripWithTimeout(conn, 5*time.Second) {
		t.Fatal("REALITY Vision handshake or data flow failed")
	}
	wrong, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = source.ApplyEgress(makePlan(2, base64.RawURLEncoding.EncodeToString(wrong.PublicKey().Bytes()))); err != nil {
		t.Fatal(err)
	}
	bad, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", echo.Port))
	if err == nil {
		defer bad.Close()
		if principalRoundTrip(bad) {
			t.Fatal("wrong REALITY public key accepted")
		}
	}
	if !principalRoundTripWithTimeout(conn, 5*time.Second) {
		t.Fatal("failed new REALITY handshake interrupted existing stream")
	}
	t.Log("actual VLESS/REALITY/Vision TCP echo with independent encrypted principal; wrong public key denied; existing stream retained")
}
