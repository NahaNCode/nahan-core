package manager

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	legacySS "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

func TestEngineUpgradeVlessTransportRoundTrips(t *testing.T) {
	for _, network := range []string{"raw", "ws", "xhttp"} {
		t.Run(network, func(t *testing.T) {
			stream := map[string]any{"network": network, "security": "none"}
			if network == "ws" {
				stream["wsSettings"] = map[string]any{"path": "/qa-upgrade"}
			}
			if network == "xhttp" {
				stream["xhttpSettings"] = map[string]any{"path": "/qa-upgrade", "mode": "packet-up"}
			}
			_, port, credential := principalFixtureWithStream(t, "vless", stream)
			document, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"protocol": "vless", "streamSettings": stream, "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": credential.ID, "encryption": "none"}}}}}}}})
			cfg, err := core.LoadConfig("json", strings.NewReader(string(document)))
			if err != nil {
				t.Fatal(err)
			}
			client, err := core.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			if err = client.Start(); err != nil {
				t.Fatal(err)
			}
			target := principalEcho(t)
			for i := 0; i < 10; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				conn, err := core.Dial(ctx, client, xnet.TCPDestination(target.Address, target.Port))
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				ok := principalRoundTripWithTimeout(conn, 3*time.Second)
				conn.Close()
				cancel()
				if !ok {
					t.Fatalf("%s transfer %d failed", network, i)
				}
			}
		})
	}
}

// Exercise the new native server with the independent client used before this upgrade.
func TestEngineUpgradeSS2022LegacyClientTCPAndUDP(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			keySize := 32
			if method == "2022-blake3-aes-128-gcm" {
				keySize = 16
			}
			password := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, keySize))
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			raw := fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"shadowsocks","settings":{"method":%q,"password":%q,"network":"tcp,udp"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]}`, port, method, password)
			var cfg conf.Config
			if err = json.Unmarshal([]byte(raw), &cfg); err != nil {
				t.Fatal(err)
			}
			built, err := cfg.Build()
			if err != nil {
				t.Fatal(err)
			}
			server, err := core.New(built)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if err = server.Start(); err != nil {
				t.Fatal(err)
			}
			client, err := legacySS.NewWithPassword(method, password, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				c, err := echo.Accept()
				if err == nil {
					defer c.Close()
					io.Copy(c, c)
				}
			}()
			underlying, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			underlying.SetDeadline(time.Now().Add(3 * time.Second))
			conn, err := client.DialConn(underlying, M.ParseSocksaddr(echo.Addr().String()))
			if err != nil {
				underlying.Close()
				t.Fatal(err)
			}
			payload := []byte("legacy-client-native-server")
			if _, err = conn.Write(payload); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			response := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, response); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			conn.Close()
			if !bytes.Equal(payload, response) {
				t.Fatal("TCP payload changed")
			}
			udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udpEcho.Close()
			go func() {
				b := make([]byte, 2048)
				n, a, e := udpEcho.ReadFrom(b)
				if e == nil {
					udpEcho.WriteTo(b[:n], a)
				}
			}()
			udpRaw, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer udpRaw.Close()
			udpRaw.SetDeadline(time.Now().Add(3 * time.Second))
			packet := client.DialPacketConn(udpRaw)
			defer packet.Close()
			if _, err = packet.WriteTo(payload, udpEcho.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			response = make([]byte, 2048)
			n, _, err := packet.ReadFrom(response)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, response[:n]) {
				t.Fatal("UDP payload changed")
			}
		})
	}
}
