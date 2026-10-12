package xdispatcher

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport"
)

func TestDownstreamEOFInterruptsPhysicalInbound(t *testing.T) {
	client, inbound := net.Pipe()
	server, remote := net.Pipe()
	defer client.Close()
	defer inbound.Close()
	defer server.Close()
	defer remote.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Conn: inbound})
	link := (&DefaultDispatcher{}).wrapLink(ctx, &transport.Link{
		Reader: buf.NewReader(inbound), Writer: buf.NewWriter(inbound),
	})
	finished := make(chan struct{})
	go func() {
		singbridge.CopyConn(ctx, inbound, link, server)
		close(finished)
	}()
	go func() { io.Copy(remote, remote) }()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "echo" {
		t.Fatal("payload changed")
	}
	remote.Close()
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("downstream EOF retained upstream copy worker")
	}
}

type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error { c.closed.Store(true); return nil }

func TestMuxPipeInterruptDoesNotClosePhysicalConnection(t *testing.T) {
	physical := &trackedConn{}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: physical})
	incoming, outgoing, err := (&DefaultDispatcher{}).getLink(ctx, xnet.Network_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(incoming.Reader)
	defer common.Interrupt(incoming.Writer)
	defer common.Interrupt(outgoing.Writer)
	common.Interrupt(outgoing.Reader)
	if physical.closed.Load() {
		t.Fatal("Mux substream closed shared physical connection")
	}
}
