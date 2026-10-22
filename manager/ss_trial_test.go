package manager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSTrialIndependentPasswordIdempotenceAndExpiry(t *testing.T) {
	lifetime := ssTrialLifetime
	ssTrialLifetime = 4 * time.Second
	defer func() { ssTrialLifetime = lifetime }()
	directory := t.TempDir()
	out := filepath.Join(directory, "out.json")
	os.WriteFile(out, []byte(`[{"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]`), 0600)
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}, OutboundConfigPath: out})
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	const coreID = "11111111-1111-4111-8111-111111111111"
	const jobID = "22222222-2222-4222-8222-222222222222"
	payload, _ := json.Marshal(map[string]any{"address": "127.0.0.1", "publicKey": base64.StdEncoding.EncodeToString(spki), "profile": map[string]any{"protocol": "shadowsocks", "listen": "127.0.0.1", "port": 31003, "settings": map[string]any{"method": "2022-blake3-aes-128-gcm", "password": "secret://core/" + coreID + "/" + jobID, "network": "tcp,udp"}}})
	sealed, err := m.SSTrial(payload, coreID, jobID)
	if err != nil {
		t.Fatal(err)
	}
	again, err := m.SSTrial(payload, coreID, jobID)
	if err != nil || again != sealed {
		t.Fatal("retry created different credentials")
	}
	wrapped, _ := base64.StdEncoding.DecodeString(sealed.WrappedKey)
	raw, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, nil)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(raw)
	gcm, _ := cipher.NewGCM(block)
	nonce, _ := base64.StdEncoding.DecodeString(sealed.Nonce)
	encrypted, _ := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	plain, err := gcm.Open(nil, nonce, encrypted, []byte("nahan-ss-test:"+coreID+":"+jobID))
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(string(plain))
	if err != nil {
		t.Fatal(err)
	}
	password, _ := uri.User.Password()
	psk, err := base64.StdEncoding.DecodeString(password)
	if err != nil || len(psk) != 16 || uri.Port() == "31003" {
		t.Fatal("not an independent temporary credential")
	}
	conn, err := net.DialTimeout("tcp", uri.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	tag := "nahan-ss-trial-" + jobID
	email := fmt.Sprintf("%s|trial|%d", tag, mustPort(uri))
	bucket, limited, rejected := dispatcher.Limiter.GetUserBucket(tag, email, "127.0.0.1")
	if rejected || !limited || bucket == nil || float64(bucket.Limit()) != float64(10*1000000/8) {
		t.Fatal("trial speed limit is not 10 Mbps")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		connection, e := echo.Accept()
		if e == nil {
			defer connection.Close()
			io.Copy(connection, connection)
		}
	}()
	document, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": mustPort(uri), "method": uri.User.Username(), "password": password}}}}}})
	config, err := core.LoadConfig("json", strings.NewReader(string(document)))
	if err != nil {
		t.Fatal(err)
	}
	client, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	active, err := core.Dial(context.Background(), client, xnet.TCPDestination(xnet.IPAddress(net.ParseIP("127.0.0.1")), xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	active.SetDeadline(time.Now().Add(time.Second))
	if _, err = active.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 1)
	if _, err = io.ReadFull(active, reply); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4500 * time.Millisecond)
	active.SetDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = active.Write([]byte("b"))
	if _, err = active.Read(reply); err == nil {
		t.Fatal("expired trial session stayed usable")
	}
	if conn, err = net.DialTimeout("tcp", uri.Host, 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("expired listener remains open")
	}
}
func mustPort(uri *url.URL) int { var port int; fmt.Sscan(uri.Port(), &port); return port }

func TestSSTrialBindCollisionCleansOnlyFailedCandidate(t *testing.T) {
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}})
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	build := func(port int) *core.InboundHandlerConfig {
		t.Helper()
		raw := fmt.Sprintf(`{"protocol":"shadowsocks","tag":"trial-collision-regression","listen":"127.0.0.1","port":%d,"settings":{"method":"2022-blake3-aes-128-gcm","password":"BwcHBwcHBwcHBwcHBwcHBw==","network":"tcp"}}`, port)
		var config conf.InboundDetourConfig
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if err != nil {
			t.Fatal(err)
		}
		return built
	}
	if addSSTrialInbound(m.Server, build(busy.Addr().(*net.TCPAddr).Port)) == nil {
		t.Fatal("busy port accepted")
	}
	handlers := m.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if _, err := handlers.GetHandler(context.Background(), "trial-collision-regression"); err == nil {
		t.Fatal("failed bind left a registered tag")
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	if err := addSSTrialInbound(m.Server, build(port)); err != nil {
		t.Fatal("retry could not use a free port", err)
	}
	original, err := handlers.GetHandler(context.Background(), "trial-collision-regression")
	if err != nil {
		t.Fatal(err)
	}
	if addSSTrialInbound(m.Server, build(busy.Addr().(*net.TCPAddr).Port)) == nil {
		t.Fatal("duplicate live tag accepted")
	}
	retained, err := handlers.GetHandler(context.Background(), "trial-collision-regression")
	if err != nil || retained != original {
		t.Fatal("failed candidate removed a different live handler", err)
	}
}
