package regression

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport"
)

type endedReader struct{ err error }

func (r endedReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, r.err }

func TestUDPEndIsNotSuccessfulPacket(t *testing.T) {
	for _, err := range []error{io.EOF, context.Canceled, io.ErrClosedPipe} {
		t.Run(err.Error(), func(t *testing.T) {
			timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
			defer timer.SetTimeout(0)
			conn := &singbridge.PacketConnWrapper{Reader: endedReader{err}, T: timer}
			buffer := B.New()
			defer buffer.Release()
			_, got := conn.ReadPacket(buffer)
			if !errors.Is(got, err) {
				t.Fatalf("ended UDP session returned success: got %v, want %v", got, err)
			}
		})
	}
}

func TestTCPBridgeCloseStopsTimer(t *testing.T) {
	closed := make(chan struct{})
	timer := signal.CancelAfterInactivity(context.Background(), func() { close(closed) }, time.Hour)
	defer timer.SetTimeout(0)
	conn := &singbridge.PipeConnWrapper{T: timer}
	conn.Close()
	conn.Close()
	select {
	case <-closed:
	default:
		t.Fatal("closed bridge retains its timer and session references")
	}
}

func TestUDPBridgeCloseStopsTimer(t *testing.T) {
	closed := make(chan struct{})
	timer := signal.CancelAfterInactivity(context.Background(), func() { close(closed) }, time.Hour)
	defer timer.SetTimeout(0)
	conn := &singbridge.PacketConnWrapper{T: timer}
	conn.Close()
	select {
	case <-closed:
	default:
		t.Fatal("closed UDP bridge retains timer references")
	}
}

type packetPeer struct {
	net.Conn
	done   chan struct{}
	once   sync.Once
	writes atomic.Int64
}

func (p *packetPeer) ReadPacket(*B.Buffer) (M.Socksaddr, error) {
	<-p.done
	return M.Socksaddr{}, io.EOF
}
func (p *packetPeer) WritePacket(buffer *B.Buffer, _ M.Socksaddr) error {
	p.writes.Add(1)
	buffer.Release()
	return nil
}
func (p *packetPeer) Close() error {
	p.once.Do(func() { close(p.done) })
	return nil
}

func TestEndedUDPSessionsDoNotKeepCopyWorkers(t *testing.T) {
	for i := 0; i < 100; i++ {
		peer := &packetPeer{done: make(chan struct{})}
		timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
		source := &singbridge.PacketConnWrapper{Reader: endedReader{io.EOF}, T: timer}
		done := make(chan struct{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		go func() {
			bufio.CopyPacketConn(ctx, source, peer)
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			peer.Close()
			t.Fatal("ended session kept copy workers alive")
		}
		cancel()
		timer.SetTimeout(0)
		if peer.writes.Load() != 0 {
			t.Fatal("EOF emitted empty UDP traffic")
		}
	}
}

func TestTCPBridgeRoundTripAndDisconnect(t *testing.T) {
	client, inbound := net.Pipe()
	server, remote := net.Pipe()
	defer client.Close()
	defer inbound.Close()
	defer server.Close()
	defer remote.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	finished := make(chan struct{})
	go func() {
		singbridge.CopyConn(ctx, inbound, &transport.Link{
			Reader: buf.NewReader(inbound), Writer: buf.NewWriter(inbound),
		}, server)
		close(finished)
	}()
	go func() { io.Copy(remote, remote) }()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte("round-trip")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("round-trip"))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "round-trip" {
		t.Fatal("payload changed")
	}
	client.Close()
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("TCP disconnect left copy workers blocked")
	}
}
