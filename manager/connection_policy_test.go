package manager

import (
	"context"
	"fmt"
	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/connectionpolicy"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConnectionPolicyHotReloadPreservesOpenConnection(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	reserve, _ := net.Listen("tcp", "127.0.0.1:0")
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	dir := t.TempDir()
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	credential := "5395f753-8ac4-484e-8f02-40c80e0aa05d"
	os.WriteFile(in, []byte(fmt.Sprintf(`[{"tag":"entry","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":%q,"email":"entry|qa|1"}]}}]`, port, credential)), 0600)
	os.WriteFile(out, []byte(fmt.Sprintf(`[{"tag":"entry","protocol":"freedom","settings":{"redirect":%q,"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]`, echo.Addr().String())), 0600)
	m := New(&Config{LogConfig: &LogConfig{Level: "none"}, InboundConfigPath: in, OutboundConfigPath: out})
	if err := m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	users := []api.SubscriptionInfo{{UID: 1, Email: "qa"}}
	if err := dispatcher.Limiter.AddInboundLimiter("entry", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	document := fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"encryption":"none"}]}]},"streamSettings":{"network":"raw","security":"none"}}]}`, port, credential)
	cfg, err := core.LoadConfig("json", strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	client, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	dial := func() net.Conn {
		c, e := core.Dial(context.Background(), client, xnet.TCPDestination(xnet.ParseAddress("policy.example.com"), 443))
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		return c
	}
	exchange := func(c net.Conn) bool {
		result := make(chan bool, 1)
		go func() {
			_, e := c.Write([]byte("ping"))
			if e != nil {
				result <- false
				return
			}
			b := make([]byte, 4)
			_, e = io.ReadFull(c, b)
			result <- e == nil && string(b) == "ping"
		}()
		select {
		case ok := <-result:
			return ok
		case <-time.After(2 * time.Second):
			c.Close()
			return false
		}
	}
	live := dial()
	defer live.Close()
	if !exchange(live) {
		t.Fatal("initial connection failed")
	}
	if err := dispatcher.ConnectionPolicy.Replace(connectionpolicy.Snapshot{Revision: 1, Rules: []connectionpolicy.Rule{{ID: "deny", Action: "block", Domains: []string{"example.com"}, Ports: "443", Network: "tcp"}}}); err != nil {
		t.Fatal(err)
	}
	if !exchange(live) {
		t.Fatal("policy reload terminated active connection")
	}
	blocked := dial()
	if exchange(blocked) {
		t.Fatal("new connection bypassed policy")
	}
	blocked.Close()
	if err := dispatcher.ConnectionPolicy.Replace(connectionpolicy.Snapshot{Revision: 2}); err != nil {
		t.Fatal(err)
	}
	restored := dial()
	defer restored.Close()
	if !exchange(restored) {
		t.Fatal("disabled policy not cleared")
	}
}
