package cmd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/google/uuid"
)

func TestManagedHeartbeatAndManifestSurviveBlockedJobs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var manifestCalls atomic.Int32
	beats := make(chan struct{}, 10)
	blocked := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/manifest"):
			manifestCalls.Add(1)
			w.Write([]byte(`{"revision":1,"nodes":[]}`))
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			select {
			case beats <- struct{}{}:
			default:
			}
			w.Write([]byte(`{}`))
		case strings.HasSuffix(r.URL.Path, "/jobs"):
			once.Do(func() { close(blocked) })
			<-r.Context().Done()
		default:
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	key := filepath.Join(t.TempDir(), "core.key")
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	panel, err := controlplane.New(&controlplane.Config{APIHost: server.URL, CoreID: "11111111-1111-4111-8111-111111111111", KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	active, config, transfer := managedTransferFixture(t)
	defer active.Close()
	transfer()
	done := make(chan error, 1)
	go func() {
		done <- serveManagedControl(ctx, panel, &active, config, &controlplane.Manifest{Revision: 1}, nil, "")
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("control workers did not stop")
		}
	}()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("jobs did not start")
	}
	// Discard the first heartbeat, which may precede the blocked job.
	select {
	case <-beats:
	default:
	}
	select {
	case <-beats:
	case <-time.After(15 * time.Second):
		t.Fatal("job timeout starved heartbeat")
	}
	deadline := time.Now().Add(3 * time.Second)
	for manifestCalls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if manifestCalls.Load() < 2 {
		t.Error("job timeout starved manifest polling")
	}
	transfer()
}

// Real engine and retained authenticated stream; no production key or external network.
func managedTransferFixture(t *testing.T) (*manager.Manager, *manager.Config, func()) {
	t.Helper()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	dir := t.TempDir()
	id := uuid.New()
	inbound := fmt.Sprintf(`[{"tag":"control-lab","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"%s"}]}}]`, port, id)
	outbound := `[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]`
	for name, data := range map[string]string{"in.json": inbound, "out.json": outbound} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := &manager.Config{LogConfig: &manager.LogConfig{Level: "none"}, InboundConfigPath: filepath.Join(dir, "in.json"), OutboundConfigPath: filepath.Join(dir, "out.json")}
	m := manager.New(config)
	if err = m.StartChecked(); err != nil {
		t.Fatal(err)
	}
	request := func(identity uuid.UUID) net.Conn {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		header := append([]byte{0}, identity[:]...)
		header = append(header, 0, 1)
		header = binary.BigEndian.AppendUint16(header, uint16(target.Addr().(*net.TCPAddr).Port))
		header = append(header, 1, 127, 0, 0, 1)
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = conn.Write(header); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		return conn
	}
	bad := request(uuid.New())
	bad.Write([]byte("reject"))
	response := make([]byte, 2)
	if _, err = io.ReadFull(bad, response); err == nil {
		bad.Close()
		m.Close()
		t.Fatal("unknown credential accepted")
	}
	bad.Close()
	conn := request(id)
	t.Cleanup(func() { conn.Close() })
	first := true
	exchange := func() {
		t.Helper()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		payload := []byte("management-fault-retained-stream")
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		if first {
			if _, err := io.ReadFull(conn, response); err != nil {
				t.Fatal(err)
			}
			if response[0] != 0 || response[1] != 0 {
				t.Fatal("invalid VLESS response")
			}
			first = false
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatal(err)
		}
		if string(reply) != string(payload) {
			t.Fatal("retained stream corrupted")
		}
	}
	return m, config, exchange
}

func TestManagedRevocationCancelsAllWorkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/heartbeat") {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"revision":1,"nodes":[]}`))
	}))
	defer server.Close()
	key := filepath.Join(t.TempDir(), "core.key")
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	panel, err := controlplane.New(&controlplane.Config{APIHost: server.URL, CoreID: "11111111-1111-4111-8111-111111111111", KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var active *manager.Manager
	if err = serveManagedControl(ctx, panel, &active, &manager.Config{}, &controlplane.Manifest{Revision: 1}, nil, ""); !errors.Is(err, controlplane.ErrUnauthorized) {
		t.Fatal("revoked core kept running", err)
	}
}
