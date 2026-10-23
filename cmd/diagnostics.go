package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"time"
)

// Profiles contain sensitive runtime data; never expose them on a TCP listener.
func startDiagnostics(socketPath string, status ...func() any) (func(), error) {
	if socketPath == "" {
		return func() {}, nil
	}
	if !filepath.IsAbs(socketPath) {
		return nil, fmt.Errorf("diagnostics socket must use an absolute path")
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	if len(status) > 0 {
		mux.HandleFunc("/debug/control-plane", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(status[0]())
		})
	}
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(listener)
	return func() { server.Close() }, nil
}
