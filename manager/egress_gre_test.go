package manager

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
)

const greQAID = "33333333-3333-4333-8333-333333333333"
const greQAName = "nhg333333333333"

// Run this test binary in a NEW network namespace, never on a production host:
// sudo unshare -n env NAHAN_EGRESS_KERNEL_QA=1 ./egress.test -test.run TestEgressGRE -test.v
func TestEgressGREKernelAndSSCredential(t *testing.T) {
	if os.Getenv("NAHAN_EGRESS_KERNEL_QA") != "1" {
		t.Skip("requires disposable root network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root in isolated namespace")
	}
	for _, iface := range interfaces {
		if (iface.Name != "lo" && iface.Name != "gre0" && iface.Name != "gretap0" && iface.Name != "erspan0") || iface.Flags&net.FlagUp != 0 {
			t.Fatal("refusing kernel QA outside isolated empty root network namespace")
		}
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	namespace := fmt.Sprintf("nahan-egress-qa-%d", os.Getpid())
	ip("netns", "add", namespace)
	defer exec.Command("ip", "netns", "delete", namespace).Run()
	ip("link", "set", "lo", "up")
	ip("link", "add", "qasrc", "type", "veth", "peer", "name", "qadst")
	ip("link", "set", "qadst", "netns", namespace)
	ip("addr", "add", "192.0.2.1/30", "dev", "qasrc")
	ip("link", "set", "qasrc", "up")
	ip("-n", namespace, "link", "set", "lo", "up")
	ip("-n", namespace, "addr", "add", "192.0.2.2/30", "dev", "qadst")
	ip("-n", namespace, "link", "set", "qadst", "up")
	ip("tunnel", "add", greQAName, "mode", "gre", "local", "192.0.2.1", "remote", "192.0.2.2", "key", "87")
	ip("addr", "add", "10.241.87.1/30", "dev", greQAName)
	ip("link", "set", greQAName, "mtu", "1360", "up")
	ip("-n", namespace, "tunnel", "add", greQAName, "mode", "gre", "local", "192.0.2.2", "remote", "192.0.2.1", "key", "87")
	ip("-n", namespace, "addr", "add", "10.241.87.2/30", "dev", greQAName)
	ip("-n", namespace, "link", "set", greQAName, "mtu", "1360", "up")
	dir := t.TempDir()
	const sourceID = "11111111-1111-4111-8111-111111111111"
	const targetID = "22222222-2222-4222-8222-222222222222"
	metadata, err := entryprofile.GenerateSecret(dir, targetID, greQAID, "shadowsocks-password", "2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := json.Marshal(map[string]any{"protocol": "shadowsocks", "listen": "10.241.87.2", "port": 31003, "settings": map[string]any{"method": "2022-blake3-aes-128-gcm", "password": metadata["reference"], "network": "tcp"}})
	resolved, err := entryprofile.Resolve(profile, dir, targetID)
	if err != nil {
		t.Fatal(err)
	}
	peerFile := filepath.Join(dir, "peer-profile.json")
	if err = os.WriteFile(peerFile, resolved, 0600); err != nil {
		t.Fatal(err)
	}
	key, public, err := egress.RecipientIdentity(filepath.Join(dir, "source.key"))
	if err != nil {
		t.Fatal(err)
	}
	scope := egress.CredentialScope{RouteID: greQAID, SourceCoreID: sourceID, TargetCoreID: targetID, Revision: 1, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	requestFile, resultFile := filepath.Join(dir, "principal-request.json"), filepath.Join(dir, "principal-result.json")
	request, _ := json.Marshal(PrincipalRequest{Scope: scope, Tag: "qa-peer-vless", Protocol: "vless", PublicKey: public})
	if err = os.WriteFile(requestFile, request, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	peer := exec.Command("ip", "netns", "exec", namespace, executable, "-test.run", "^TestEgressGREPeer$", "-test.v")
	peer.Env = append(os.Environ(), "NAHAN_EGRESS_PEER_PROFILE="+peerFile, "NAHAN_EGRESS_PRINCIPAL_REQUEST="+requestFile, "NAHAN_EGRESS_PRINCIPAL_RESULT="+resultFile)
	output, err := peer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	peer.Stderr = os.Stderr
	if err = peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { peer.Process.Kill(); peer.Wait() }()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		sent := false
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "GRE_PEER_READY") && !sent {
				ready <- true
				sent = true
			}
		}
		if !sent {
			ready <- false
		}
	}()
	select {
	case success := <-ready:
		if !success {
			t.Fatal("peer failed to start")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("peer readiness timeout")
	}
	sealed, err := egress.ExportCredential(profile, dir, targetID, public, scope)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := egress.OpenCredential(sealed, key, sourceID, scope)
	if err != nil {
		t.Fatal(err)
	}
	localCredential := strings.Repeat("a", 64)
	if err = egress.ImportCredential(dir, sourceID, localCredential, key, egress.CredentialImport{ID: greQAID, Scope: scope, Sealed: sealed}); err != nil {
		t.Fatal(err)
	}
	binding := egress.CredentialBinding{TransferID: greQAID, RouteID: greQAID, Revision: 1, Method: credential.Method}
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}, ResolveEgressCredential: func(b egress.CredentialBinding) (egress.SSCredential, error) {
		return egress.ReadCredential(dir, sourceID, localCredential, b)
	}, ResolveEgressPrincipal: func(b egress.PrincipalBinding) (egress.PrincipalCredential, error) {
		return egress.ReadPrincipal(dir, sourceID, localCredential, b)
	}})
	if err = m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	config, _ := json.Marshal(map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": "unused.example", "port": 31003, "method": credential.Method}}}})
	plan := EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa", Outbound: "ss-gre"}}}, Profiles: []EgressProfile{{ID: "ss-gre", Config: config, Secret: &binding, Tunnel: &egress.TunnelBinding{ID: greQAID, Interface: greQAName, LocalCIDR: "10.241.87.1/30", PeerIP: "10.241.87.2"}}}}
	counter := func(name string) uint64 {
		data, err := exec.Command("ip", "-j", "-s", "link", "show", greQAName).Output()
		if err != nil {
			t.Fatal(err)
		}
		var links []struct {
			Stats64 map[string]struct {
				Packets uint64 `json:"packets"`
			} `json:"stats64"`
		}
		if err := json.Unmarshal(data, &links); err != nil || len(links) != 1 {
			t.Fatal("invalid kernel link counters", err)
		}
		return links[0].Stats64[name].Packets
	}
	beforeTx, beforeRx := counter("tx"), counter("rx")
	if err = m.ApplyEgress(plan); err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "qa"})
	conn, err := core.Dial(ctx, m.Server, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 18080))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	timer := time.AfterFunc(10*time.Second, func() { conn.Close() })
	defer timer.Stop()
	if _, err = conn.Write([]byte("GRE-SS-REAL")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 11)
	if _, err = io.ReadFull(conn, response); err != nil || string(response) != "GRE-SS-REAL" {
		t.Fatal("encrypted SS flow over GRE failed", err)
	}
	if counter("tx") <= beforeTx || counter("rx") <= beforeRx {
		t.Fatal("SS traffic did not traverse actual GRE interface")
	}
	// A correctly scoped but wrong server PSK must not authorize new traffic,
	// and staging that new route must not terminate the previously open flow.
	badScope := scope
	badScope.Revision = 2
	label, err := badScope.Label()
	if err != nil {
		t.Fatal(err)
	}
	wrong := egress.SSCredential{Method: credential.Method, Password: base64.StdEncoding.EncodeToString(make([]byte, 16))}
	badJSON, _ := json.Marshal(wrong)
	badSealed, err := entryprofile.Seal(badJSON, public, label)
	if err != nil {
		t.Fatal(err)
	}
	const badTransfer = "55555555-5555-4555-8555-555555555555"
	if err = egress.ImportCredential(dir, sourceID, localCredential, key, egress.CredentialImport{ID: badTransfer, Scope: badScope, Sealed: badSealed}); err != nil {
		t.Fatal(err)
	}
	badBinding := binding
	badBinding.TransferID = badTransfer
	badBinding.Revision = 2
	badPlan := plan
	badPlan.Snapshot.Revision = 2
	badProfile := plan.Profiles[0]
	badProfile.Secret = &badBinding
	badPlan.Profiles = []EgressProfile{badProfile}
	if err = m.ApplyEgress(badPlan); err != nil {
		t.Fatal(err)
	}
	denied, err := core.Dial(ctx, m.Server, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 18080))
	if err == nil {
		deadline := time.AfterFunc(2*time.Second, func() { denied.Close() })
		_, _ = denied.Write([]byte("DENIED"))
		data := make([]byte, 6)
		_, readErr := io.ReadFull(denied, data)
		deadline.Stop()
		denied.Close()
		if readErr == nil {
			t.Fatal("incorrect SS credential accepted or fell back to direct")
		}
	}
	if _, err = conn.Write([]byte("RETAINED")); err != nil {
		t.Fatal("changing SS route closed existing stream", err)
	}
	retained := make([]byte, 8)
	if _, err = io.ReadFull(conn, retained); err != nil || string(retained) != "RETAINED" {
		t.Fatal("existing SS stream was not retained", err)
	}
	principalResult, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatal(err)
	}
	var principalImport egress.CredentialImport
	if err = json.Unmarshal(principalResult, &principalImport); err != nil {
		t.Fatal(err)
	}
	if err = egress.ImportPrincipal(dir, sourceID, localCredential, key, principalImport); err != nil {
		t.Fatal(err)
	}
	principalBinding := egress.PrincipalBinding{TransferID: greQAID, RouteID: greQAID, TargetCoreID: targetID, Revision: 1, Protocol: "vless"}
	vlessConfig := json.RawMessage(`{"protocol":"vless","settings":{"vnext":[{"address":"unused.example","port":31004}]}}`)
	vlessPlan := EgressPlan{Snapshot: egress.Snapshot{Revision: 3, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa", Outbound: greQAID}}}, Profiles: []EgressProfile{{ID: greQAID, Config: vlessConfig, Principal: &principalBinding, Tunnel: plan.Profiles[0].Tunnel}}}
	if err = m.ApplyEgress(vlessPlan); err != nil {
		t.Fatal(err)
	}
	vlessConnection, err := core.Dial(ctx, m.Server, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 18080))
	if err != nil {
		t.Fatal(err)
	}
	defer vlessConnection.Close()
	vlessTimer := time.AfterFunc(3*time.Second, func() { vlessConnection.Close() })
	defer vlessTimer.Stop()
	if _, err = vlessConnection.Write([]byte("VLESS-GRE")); err != nil {
		t.Fatal(err)
	}
	vlessResponse := make([]byte, 9)
	if _, err = io.ReadFull(vlessConnection, vlessResponse); err != nil || string(vlessResponse) != "VLESS-GRE" {
		t.Fatal("VLESS outbound over actual GRE failed", err)
	}
	routes, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil || len(routes) != 0 {
		t.Fatal("QA changed default routing")
	}
	t.Log("PASS: SS2022 and independently provisioned/sealed/imported VLESS principal over GRE; wrong SS PSK denied; previous stream preserved; no default route")
}

func TestEgressGREPeer(t *testing.T) {
	filename := os.Getenv("NAHAN_EGRESS_PEER_PROFILE")
	if filename == "" {
		t.Skip("GRE QA child only")
	}
	profile, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}})
	if err = m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for i, raw := range [][]byte{profile, []byte(`{"protocol":"vless","listen":"10.241.87.2","port":31004,"settings":{"clients":[],"decryption":"none"}}`)} {
		var config conf.InboundDetourConfig
		if err = json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		config.Tag = []string{"qa-peer-ss", "qa-peer-vless"}[i]
		built, buildErr := config.Build()
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		if err = core.AddInboundHandler(m.Server, built); err != nil {
			t.Fatal(err)
		}
	}
	dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	users := []api.SubscriptionInfo{}
	if err = dispatcher.Limiter.AddInboundLimiter("qa-peer-vless", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	allow := EgressPlan{Snapshot: egress.Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []egress.Binding{{Inbound: "qa-peer-ss", Outbound: "qa-echo"}, {Inbound: "qa-peer-vless", Outbound: "qa-echo"}}}, Profiles: []EgressProfile{{ID: "qa-echo", Config: json.RawMessage(`{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}`)}}}
	if err = m.ApplyEgress(allow); err != nil {
		t.Fatal(err)
	}
	request, err := os.ReadFile(os.Getenv("NAHAN_EGRESS_PRINCIPAL_REQUEST"))
	if err != nil {
		t.Fatal(err)
	}
	var r PrincipalRequest
	if err = json.Unmarshal(request, &r); err != nil {
		t.Fatal(err)
	}
	sealed, err := m.ProvisionEgressPrincipal(principalTarget, r)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(egress.CredentialImport{ID: greQAID, Kind: "principal", Scope: r.Scope, Sealed: sealed})
	if err = os.WriteFile(os.Getenv("NAHAN_EGRESS_PRINCIPAL_RESULT"), result, 0600); err != nil {
		t.Fatal(err)
	}
	echo, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	fmt.Println("GRE_PEER_READY")
	for {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		go func() { defer conn.Close(); io.Copy(conn, conn) }()
	}
}
