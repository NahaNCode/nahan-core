package manager

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/utility/exitroute"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// Execute only in a new, empty network namespace with NAHAN_EXIT_KERNEL_QA=1.
func TestDestinationExitSharedSSRealSockets(t *testing.T) {
	if os.Getenv("NAHAN_EXIT_KERNEL_QA") != "1" {
		t.Skip("requires disposable root network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required in isolated namespace")
	}
	for _, iface := range interfaces {
		if (iface.Name != "lo" && iface.Name != "gre0" && iface.Name != "gretap0" && iface.Name != "erspan0") || iface.Flags&net.FlagUp != 0 {
			t.Fatal("refusing nonempty network namespace")
		}
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip: %v %s", err, out)
		}
	}
	ip("link", "set", "lo", "up")
	for _, address := range []string{"192.0.2.146/32", "192.0.2.197/32", "1.1.1.1/32", "10.241.88.1/30", "10.241.88.2/30", "10.241.87.1/30", "10.241.87.2/30"} {
		ip("addr", "add", address, "dev", "lo")
	}
	m := New(&Config{LogConfig: &LogConfig{Level: "debug"}})
	if err = m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var input conf.InboundDetourConfig
	raw := `{"protocol":"shadowsocks","tag":"Shadowsocks_31006_17","listen":"0.0.0.0","port":31006,"settings":{"method":"aes-128-gcm","password":"disposable-qa-password","network":"tcp,udp"}}`
	if err = json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatal(err)
	}
	built, err := input.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err = core.AddInboundHandler(m.Server, built); err != nil {
		t.Fatal(err)
	}
	s := exitroute.Snapshot{Revision: 1, LeaseSeconds: 30, Rules: []exitroute.Rule{
		{ID: principalSource, Mode: "shared", Inbound: input.Tag, SourceIP: "10.241.88.1", LocalIP: "10.241.88.2", ExitIP: "192.0.2.146", Active: true},
		{ID: principalTarget, Mode: "shared", Inbound: input.Tag, SourceIP: "10.241.87.1", LocalIP: "10.241.87.2", ExitIP: "192.0.2.197", Active: true},
	}}
	if err = m.ApplyExitRoutes(s); err != nil {
		t.Fatal(err)
	}
	// A globally routable target avoids the runtime's reserved-target guard;
	// the address exists only on loopback in this disposable namespace.
	echo, err := net.Listen("tcp", "1.1.1.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	udp, err := net.ListenPacket("udp", "1.1.1.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		data := make([]byte, 1024)
		for {
			_, peer, err := udp.ReadFrom(data)
			if err != nil {
				return
			}
			udp.WriteTo([]byte(peer.(*net.UDPAddr).IP.String()), peer)
		}
	}()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.WriteString(conn, strings.Split(conn.RemoteAddr().String(), ":")[0]+"\n")
			}()
		}
	}()
	for _, r := range s.Rules {
		cfgJSON, _ := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"protocol": "shadowsocks", "sendThrough": r.SourceIP, "settings": map[string]any{"servers": []any{map[string]any{"address": r.LocalIP, "port": 31006, "method": "aes-128-gcm", "password": "disposable-qa-password"}}}}}})
		var cfg conf.Config
		if err = json.Unmarshal(cfgJSON, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg.LogConfig = &conf.LogConfig{LogLevel: "debug"}
		built, err := cfg.Build()
		if err != nil {
			t.Fatal(err)
		}
		client, err := core.New(built)
		if err != nil {
			t.Fatal(err)
		}
		if err = client.Start(); err != nil {
			client.Close()
			t.Fatal(err)
		}
		conn, err := core.Dial(context.Background(), client, xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		timer := time.AfterFunc(3*time.Second, func() { conn.Close() })
		// SS sends its target header with the first application write.
		if _, err = conn.Write([]byte("qa")); err != nil {
			t.Fatal(err)
		}
		reply, readErr := io.ReadAll(conn)
		timer.Stop()
		conn.Close()
		if readErr != nil || strings.TrimSpace(string(reply)) != r.ExitIP {
			client.Close()
			t.Fatalf("source %s expected %s observed %q: %v", r.SourceIP, r.ExitIP, reply, readErr)
		}
		packet, err := core.Dial(context.Background(), client, xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(udp.LocalAddr().(*net.UDPAddr).Port)))
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		timer = time.AfterFunc(3*time.Second, func() { packet.Close() })
		_, writeErr := packet.Write([]byte("udp-qa"))
		response := make([]byte, 128)
		n, readErr := packet.Read(response)
		timer.Stop()
		packet.Close()
		client.Close()
		if writeErr != nil || readErr != nil || string(response[:n]) != r.ExitIP {
			t.Fatalf("UDP source %s expected %s observed %q: %v %v", r.SourceIP, r.ExitIP, response[:n], writeErr, readErr)
		}
	}
	t.Log("PASS: TCP and UDP on one wildcard SS listener/port, two tunnel endpoint pairs, two observed Internet source IPs")
}
