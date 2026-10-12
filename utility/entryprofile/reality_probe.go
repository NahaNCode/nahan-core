package entryprofile

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
	realitytls "github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

// ProbeReality verifies the cover handshake with the installed engine, using an
// ephemeral loopback socket. It never binds the entry port or starts a proxy.
func ProbeReality(parent context.Context, input []byte) string {
	var document struct {
		Inbound json.RawMessage `json:"inbound"`
		Stream  struct {
			Security string          `json:"security"`
			Reality  json.RawMessage `json:"realitySettings"`
		} `json:"streamSettings"`
	}
	if json.Unmarshal(input, &document) != nil {
		return "invalid_inbound"
	}
	if len(document.Inbound) > 0 {
		return ProbeReality(parent, document.Inbound)
	}
	if document.Stream.Security != "reality" {
		return ""
	}
	var settings conf.REALITYConfig
	if json.Unmarshal(document.Stream.Reality, &settings) != nil {
		return "reality_probe_invalid"
	}
	settings.Show = false
	settings.MasterKeyLog = ""
	built, err := settings.Build()
	if err != nil {
		return "reality_probe_invalid"
	}
	server, ok := built.(*xreality.Config)
	if !ok || len(server.ServerNames) == 0 || len(server.ShortIds) == 0 {
		return "reality_probe_invalid"
	}
	key, err := ecdh.X25519().NewPrivateKey(server.PrivateKey)
	if err != nil {
		return "reality_probe_invalid"
	}
	clientSettings := conf.REALITYConfig{Fingerprint: "chrome", ServerName: server.ServerNames[0], PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortId: settings.ShortIds[0]}
	clientBuilt, err := clientSettings.Build()
	if err != nil {
		return "reality_probe_invalid"
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "reality_probe_unavailable"
	}
	defer listener.Close()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return "reality_probe_unavailable"
	}
	defer conn.Close()
	peer, err := listener.Accept()
	if err != nil {
		return "reality_probe_unavailable"
	}
	defer peer.Close()
	_ = conn.SetDeadline(deadline)
	_ = peer.SetDeadline(deadline)
	serverConfig := server.GetREALITYConfig()
	serverConfig.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		remote, err := dialer.DialContext(ctx, network, address)
		if err == nil {
			_ = remote.SetDeadline(deadline)
		}
		return remote, err
	}
	// REALITY's server requires post-handshake record detection. Use its own
	// detector, but bound the network operation rather than its unbounded helper.
	cacheKey := server.Dest + " " + server.ServerNames[0] + " 2"
	if _, ready := realitytls.GlobalPostHandshakeRecordsLens.Load(cacheKey); !ready {
		remote, err := serverConfig.DialContext(ctx, server.Type, server.Dest)
		if err != nil {
			return "reality_cover_unreachable_or_incompatible"
		}
		if serverConfig.Xver > 0 {
			if _, err = proxyproto.HeaderProxyFromAddrs(serverConfig.Xver, remote.LocalAddr(), remote.RemoteAddr()).WriteTo(remote); err != nil {
				remote.Close()
				return "reality_cover_unreachable_or_incompatible"
			}
		}
		detected := &realitytls.PostHandshakeRecordDetectConn{Conn: remote, Key: cacheKey}
		tlsConn := utls.UClient(detected, &utls.Config{ServerName: server.ServerNames[0], NextProtos: []string{"h2", "http/1.1"}}, utls.HelloChrome_Auto)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			remote.Close()
			return "reality_cover_unreachable_or_incompatible"
		}
		_, _ = io.Copy(io.Discard, tlsConn)
		remote.Close()
		if _, ready = realitytls.GlobalPostHandshakeRecordsLens.Load(cacheKey); !ready {
			return "reality_cover_unreachable_or_incompatible"
		}
	}
	done := make(chan error, 1)
	go func() {
		s, err := realitytls.Server(ctx, peer, serverConfig)
		if err == nil {
			err = s.HandshakeContext(ctx)
		}
		done <- err
	}()
	c, err := xreality.UClient(conn, clientBuilt.(*xreality.Config), ctx, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(listener.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		return "reality_cover_unreachable_or_incompatible"
	}
	defer c.Close()
	verified, ok := c.(*xreality.UConn)
	if !ok || !verified.Verified {
		return "reality_cover_unreachable_or_incompatible"
	}
	select {
	case err := <-done:
		if err != nil {
			return "reality_cover_unreachable_or_incompatible"
		}
	case <-ctx.Done():
		return "reality_cover_unreachable_or_incompatible"
	}
	return ""
}
