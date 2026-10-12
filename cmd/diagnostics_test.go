package cmd

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticsLocalSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "profile.sock")
	stop, err := startDiagnostics(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe socket permissions: %v, %v", info, err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://localhost/debug/pprof/heap")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", response.StatusCode)
	}
	stop()
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket was not removed: %v", err)
	}
}

func TestDiagnosticsDisabledOrRelative(t *testing.T) {
	stop, err := startDiagnostics("")
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := startDiagnostics("relative.sock"); err == nil {
		t.Fatal("relative socket accepted")
	}
}
