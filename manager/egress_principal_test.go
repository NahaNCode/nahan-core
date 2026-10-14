package manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/egress"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
)

const principalSource = "11111111-1111-4111-8111-111111111111"
const principalTarget = "22222222-2222-4222-8222-222222222222"
const principalRoute = "33333333-3333-4333-8333-333333333333"
const principalCustomer = "44444444-4444-4444-8444-444444444444"

func principalFixture(t *testing.T, kind string) (*Manager, int, egress.PrincipalCredential) {
	t.Helper()
	return principalFixtureWithStream(t, kind, nil)
}

func principalFixtureWithStream(t *testing.T, kind string, stream any) (*Manager, int, egress.PrincipalCredential) {
	t.Helper()
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}})
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	portListener.Close()
	settings := map[string]any{"clients": []any{map[string]any{"id": principalCustomer, "email": "qa-principal|customer|7"}}, "decryption": "none"}
	customer := egress.PrincipalCredential{Protocol: kind, ID: principalCustomer}
	if kind == "trojan" {
		customer.ID = ""
		customer.Password = "qa-customer-secret"
		settings = map[string]any{"clients": []any{map[string]any{"password": customer.Password, "email": "qa-principal|customer|7"}}}
	}
	profile := map[string]any{"protocol": kind, "tag": "qa-principal", "listen": "127.0.0.1", "port": port, "settings": settings}
	if stream != nil {
		profile["streamSettings"] = stream
	}
	raw, _ := json.Marshal(profile)
	var inboundConfig conf.InboundDetourConfig
	if err := json.Unmarshal(raw, &inboundConfig); err != nil {
		t.Fatal(err)
	}
	built, err := inboundConfig.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err = core.AddInboundHandler(m.Server, built); err != nil {
		t.Fatal(err)
	}
	d := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	users := []api.SubscriptionInfo{{UID: 7, Email: "customer"}}
	if err = d.Limiter.AddInboundLimiter("qa-principal", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	plan := EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa-principal", Outbound: "qa-echo"}}}, Profiles: []EgressProfile{{ID: "qa-echo", Config: json.RawMessage(`{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}`)}}}
	if err = m.ApplyEgress(plan); err != nil {
		t.Fatal(err)
	}
	return m, port, customer
}

func principalClient(t *testing.T, credential egress.PrincipalCredential, port int) *core.Instance {
	t.Helper()
	endpoint := map[string]any{"address": "127.0.0.1", "port": port}
	key := "vnext"
	if credential.Protocol == "trojan" {
		key = "servers"
		endpoint["password"] = credential.Password
	} else {
		endpoint["users"] = []any{map[string]any{"id": credential.ID, "encryption": "none", "security": "auto", "flow": credential.Flow}}
	}
	data, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"protocol": credential.Protocol, "settings": map[string]any{key: []any{endpoint}}}}})
	config, err := core.LoadConfig("json", strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	client, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	return client
}

func principalEcho(t *testing.T) xnet.Destination {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	return xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(listener.Addr().(*net.TCPAddr).Port))
}

func principalRoundTrip(conn net.Conn) bool {
	return principalRoundTripWithTimeout(conn, time.Second)
}

func principalRoundTripWithTimeout(conn net.Conn, timeout time.Duration) bool {
	timer := time.AfterFunc(timeout, func() { conn.Close() })
	defer timer.Stop()
	if _, err := conn.Write([]byte("principal")); err != nil {
		return false
	}
	var reply [9]byte
	_, err := io.ReadFull(conn, reply[:])
	return err == nil && string(reply[:]) == "principal"
}

func TestEgressPrincipalHotProvisionRenewAndRevokePreservesCustomer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		t.Run(kind, func(t *testing.T) {
			m, port, customer := principalFixture(t, kind)
			original := m.Server
			target := principalEcho(t)
			customerClient := principalClient(t, customer, port)
			customerConn, err := core.Dial(context.Background(), customerClient, target)
			if err != nil {
				t.Fatal(err)
			}
			defer customerConn.Close()
			if !principalRoundTrip(customerConn) {
				t.Fatal("initial customer flow failed")
			}
			request := PrincipalRequest{Scope: egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 1, ExpiresAt: time.Now().Add(30 * time.Second).Unix()}, Tag: "qa-principal", Protocol: kind, PublicKey: base64.StdEncoding.EncodeToString(public)}
			sealed, err := m.ProvisionEgressPrincipal(principalTarget, request)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := egress.OpenPrincipal(sealed, key, principalSource, request.Scope)
			if err != nil {
				t.Fatal(err)
			}
			if credential == customer || m.Server != original {
				t.Fatal("customer identity reused or server restarted")
			}
			client := principalClient(t, credential, port)
			conn, err := core.Dial(context.Background(), client, target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if !principalRoundTrip(conn) {
				t.Fatal("principal flow failed")
			}
			request.Scope.ExpiresAt++
			renewed, err := m.ProvisionEgressPrincipal(principalTarget, request)
			if err != nil {
				t.Fatal(err)
			}
			again, err := egress.OpenPrincipal(renewed, key, principalSource, request.Scope)
			if err != nil || again != credential || !principalRoundTrip(conn) {
				t.Fatal("renewal rotated credential or interrupted stream")
			}
			if err = m.RevokeEgressPrincipal(principalRoute, principalSource, 0); err == nil {
				t.Fatal("stale revocation accepted")
			}
			if err = m.RevokeEgressPrincipal(principalRoute, principalSource, 1); err != nil {
				t.Fatal(err)
			}
			if principalRoundTrip(conn) {
				t.Fatal("revoked principal stream retained authorization")
			}
			if !principalRoundTrip(customerConn) || m.Server != original {
				t.Fatal("revocation interrupted customer")
			}
			if _, err = m.ProvisionEgressPrincipal(principalTarget, request); err == nil {
				t.Fatal("revoked revision revived")
			}
			request.Scope.Revision++
			if _, err = m.ProvisionEgressPrincipal(principalTarget, request); err != nil {
				t.Fatal(err)
			}
			request.Scope.Revision--
			if _, err = m.ProvisionEgressPrincipal(principalTarget, request); err == nil {
				t.Fatal("stale principal revision accepted")
			}
			t.Log(fmt.Sprintf("%s: independent real principal flow, renewal, scoped revoke; customer stream retained", kind))
		})
	}
}

func TestEgressPrincipalExpiryFailsClosedAndCannotReuseExpiredRevision(t *testing.T) {
	m, _, _ := principalFixture(t, "vless")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	r := PrincipalRequest{Scope: egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 1, ExpiresAt: time.Now().Add(2 * time.Second).Unix()}, Tag: "qa-principal", Protocol: "vless", PublicKey: base64.StdEncoding.EncodeToString(public)}
	if _, err := m.ProvisionEgressPrincipal(principalTarget, r); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(time.Unix(r.Scope.ExpiresAt, 0)) + 100*time.Millisecond)
	users, err := m.principalTarget(r.Tag, r.Protocol)
	if err != nil {
		t.Fatal(err)
	}
	if users.GetUser(context.Background(), fmt.Sprintf("nahan-egress/%s/%s/1", principalRoute, principalSource)) != nil {
		t.Fatal("expired user not removed")
	}
	r.Scope.ExpiresAt = time.Now().Add(time.Minute).Unix()
	if _, err := m.ProvisionEgressPrincipal(principalTarget, r); err == nil {
		t.Fatal("expired revision renewed after authorization loss")
	}
}

func TestEgressPrincipalRenewalTimerCannotRevokeNewLease(t *testing.T) {
	m, _, _ := principalFixture(t, "vless")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	r := PrincipalRequest{Scope: egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 1, ExpiresAt: time.Now().Add(2 * time.Second).Unix()}, Tag: "qa-principal", Protocol: "vless", PublicKey: base64.StdEncoding.EncodeToString(public)}
	if _, err = m.ProvisionEgressPrincipal(principalTarget, r); err != nil {
		t.Fatal(err)
	}
	previousDeadline := r.Scope.ExpiresAt
	r.Scope.ExpiresAt += 2
	if _, err = m.ProvisionEgressPrincipal(principalTarget, r); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(time.Unix(previousDeadline, 0)) + 100*time.Millisecond)
	users, err := m.principalTarget(r.Tag, r.Protocol)
	if err != nil {
		t.Fatal(err)
	}
	email := fmt.Sprintf("nahan-egress/%s/%s/1", principalRoute, principalSource)
	if users.GetUser(context.Background(), email) == nil {
		t.Fatal("old timer revoked a renewed principal")
	}
	time.Sleep(time.Until(time.Unix(r.Scope.ExpiresAt, 0)) + 100*time.Millisecond)
	if users.GetUser(context.Background(), email) != nil {
		t.Fatal("renewed principal outlived its deadline")
	}
}

func TestEgressPrincipalCapacityIncludesRotatedIdentitiesButAllowsRenewal(t *testing.T) {
	m, _, _ := principalFixture(t, "vless")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	r := PrincipalRequest{Scope: egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 1, ExpiresAt: time.Now().Add(time.Minute).Unix()}, Tag: "qa-principal", Protocol: "vless", PublicKey: base64.StdEncoding.EncodeToString(public)}
	if _, err = m.ProvisionEgressPrincipal(principalTarget, r); err != nil {
		t.Fatal(err)
	}
	m.principalInstalls = 512
	if _, err = m.ProvisionEgressPrincipal(principalTarget, r); err != nil {
		t.Fatal("existing principal renewal blocked at capacity", err)
	}
	r.Scope.Revision++
	if _, err = m.ProvisionEgressPrincipal(principalTarget, r); err == nil {
		t.Fatal("rotations exceeded bounded retained revocation state")
	}
	if err = m.RevokeEgressPrincipal(principalRoute, principalSource, 1); err != nil {
		t.Fatal("failed capacity staging changed current principal", err)
	}
}
