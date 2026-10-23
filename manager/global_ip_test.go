package manager

import (
	"context"
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
	"github.com/NahaNCode/nahan-core/utility/limiter"
	"github.com/google/uuid"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
)

func TestTwoRuntimeGlobalIPAdmissionWithRealVLESSClients(t *testing.T) {
	binary, err := exec.LookPath("redis-server")
	if err != nil {
		if os.Getenv("NAHAN_REQUIRE_REDIS_TESTS") == "1" {
			t.Fatal(err)
		}
		t.Skip("redis-server required")
	}
	socket := filepath.Join(t.TempDir(), "redis.sock")
	redis := exec.Command(binary, "--port", "0", "--unixsocket", socket, "--save", "", "--appendonly", "no")
	if err := redis.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { redis.Process.Kill(); redis.Wait() })
	ready := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if conn, e := net.DialTimeout("unix", socket, 20*time.Millisecond); e == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated Redis unavailable")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	credential := uuid.NewString()
	dispatchers := make(map[string]*xdispatcher.DefaultDispatcher)
	start := func(tag string) int {
		t.Helper()
		reservation, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := reservation.Addr().(*net.TCPAddr).Port
		reservation.Close()
		dir := t.TempDir()
		in, out := filepath.Join(dir, "in.json"), filepath.Join(dir, "out.json")
		inbound := fmt.Sprintf(`[{"tag":%q,"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":%q,"email":%q}]}}]`, tag, port, credential, tag+"|qa|1")
		outbound := fmt.Sprintf(`[{"tag":%q,"protocol":"freedom","settings":{"redirect":%q,"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]`, tag, echo.Addr().String())
		if err := os.WriteFile(in, []byte(inbound), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, []byte(outbound), 0600); err != nil {
			t.Fatal(err)
		}
		m := New(&Config{LogConfig: &LogConfig{Level: "none"}, InboundConfigPath: in, OutboundConfigPath: out})
		if err := m.StartChecked(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close() })
		dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
		dispatchers[tag] = dispatcher
		users := []api.SubscriptionInfo{{UID: 1, Email: "qa", DeviceLimit: 1}}
		if err := dispatcher.Limiter.AddInboundLimiter(tag, 0, &users, &limiter.IPLimit{Enable: true, RedisNetwork: "unix", RedisAddr: socket, Scope: "lab", OnError: "deny"}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { dispatcher.Limiter.DeleteInboundLimiter(tag) })
		return port
	}
	a, b := start("first"), start("second")
	connect := func(port int, source string) (*core.Instance, net.Conn) {
		t.Helper()
		document := fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"vless","sendThrough":%q,"settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"encryption":"none"}]}]},"streamSettings":{"network":"raw","security":"none"}}]}`, source, port, credential)
		cfg, err := core.LoadConfig("json", strings.NewReader(document))
		if err != nil {
			t.Fatal(err)
		}
		client, err := core.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Start(); err != nil {
			client.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		conn, err := core.Dial(context.Background(), client, xnet.TCPDestination(xnet.ParseAddress("ip-limit.lab.invalid"), 443))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return client, conn
	}
	exchange := func(conn net.Conn) bool {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("test")); err != nil {
			return false
		}
		var result [4]byte
		_, err := io.ReadFull(conn, result[:])
		return err == nil && string(result[:]) == "test"
	}
	_, first := connect(a, "127.0.0.1")
	if !exchange(first) {
		t.Fatal("first real client rejected")
	}
	_, same := connect(b, "127.0.0.1")
	if !exchange(same) {
		t.Fatal("same source on another runtime consumed another slot")
	}
	_, other := connect(b, "127.0.0.2")
	if exchange(other) {
		t.Fatal("distinct real source bypassed the shared Redis cap")
	}
	if !exchange(first) {
		t.Fatal("denied new source interrupted an established connection")
	}
	users := []api.SubscriptionInfo{{UID: 1, Email: "qa", DeviceLimit: 1, SpeedLimit: 256}}
	if err := dispatchers["first"].Limiter.UpdateInboundLimiter("first", &users); err != nil {
		t.Fatal(err)
	}
	first.SetDeadline(time.Now().Add(6 * time.Second))
	payload := strings.Repeat("a", 256)
	started := time.Now()
	if _, err := io.WriteString(first, payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(first, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != payload || time.Since(started) < 600*time.Millisecond {
		t.Fatal("introduced rate ceiling did not throttle the already-established unlimited stream")
	}
}
