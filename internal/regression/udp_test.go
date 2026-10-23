package regression

import (
	"context"
	"errors"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/policy"
	ss "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/transport"
	"io"
	"net"
	"testing"
	"time"
)

type endedReader struct{ err error }

func (r endedReader) Read([]byte) (int, error) { return 0, r.err }

// Native SS2022 must preserve terminal packet errors, without an empty packet.
func TestUDPEndIsNotSuccessfulPacket(t *testing.T) {
	for _, err := range []error{io.EOF, context.Canceled, io.ErrClosedPipe} {
		t.Run(err.Error(), func(t *testing.T) {
			r := ss.UDPReader{Reader: endedReader{err}}
			mb, got := r.ReadMultiBuffer()
			defer buf.ReleaseMulti(mb)
			if !errors.Is(got, err) || len(mb) != 0 {
				t.Fatalf("terminal UDP read: packets=%d error=%v", len(mb), got)
			}
		})
	}
}

func TestNativeTCPRoundTripAndDisconnect(t *testing.T) {
	for _, downstream := range []bool{false, true} {
		t.Run(map[bool]string{false: "upstream", true: "downstream"}[downstream], func(t *testing.T) {
			client, inbound := net.Pipe()
			server, remote := net.Pipe()
			defer client.Close()
			defer inbound.Close()
			defer server.Close()
			defer remote.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				finished <- ss.TransportTCP(ctx, policy.Session{Timeouts: policy.Timeout{ConnectionIdle: time.Hour}}, buf.NewReader(inbound), buf.NewWriter(inbound), &transport.Link{Reader: buf.NewReader(server), Writer: buf.NewWriter(server)})
			}()
			go io.Copy(remote, remote)
			client.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := client.Write([]byte("round-trip")); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 10)
			if _, err := io.ReadFull(client, response); err != nil {
				t.Fatal(err)
			}
			if string(response) != "round-trip" {
				t.Fatal("payload changed")
			}
			if downstream {
				remote.Close()
			} else {
				client.Close()
			}
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal("disconnect retained copy workers")
			}
		})
	}
}
