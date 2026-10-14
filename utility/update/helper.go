package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

func Serve(ctx context.Context, e *Engine) error {
	if os.Geteuid() != 0 {
		return errors.New("updater must run as root")
	}
	if err := e.setup(); err != nil {
		return err
	}
	prior, _ := e.State()
	if err := e.Recover(ctx); err != nil {
		return err
	}
	if prior.Stage == "applying" || prior.Stage == "verifying" || prior.Stage == "rolling_back" {
		data, err := os.ReadFile(filepath.Join(e.Profile.StateDir, "pending.json"))
		var pending struct {
			Action  string  `json:"action"`
			Request Request `json:"request"`
		}
		if err == nil && json.Unmarshal(data, &pending) == nil && pending.Request.ID == prior.ID {
			state, _ := e.State()
			success := pending.Action == "rollback"
			if success {
				state.Digest = state.PreviousDigest
				state.Version = state.PreviousVersion
				state.Error = ""
				e.save(&state, "rolled_back")
			}
			go func() {
				worker, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				e.report(worker, pending.Request, state, success)
			}()
		}
	}
	directory := filepath.Dir(Socket(e.Profile.CoreID))
	// Both directories are recreated after reboot under the helper's restrictive umask.
	for _, current := range []string{filepath.Dir(directory), directory} {
		if err := os.MkdirAll(current, 0711); err != nil {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe updater socket directory")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
			return errors.New("updater socket directory must be root-owned")
		}
		if err := os.Chmod(current, 0711); err != nil {
			return err
		}
	}
	path := Socket(e.Profile.CoreID)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("unsafe updater socket")
		}
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return errors.New("updater already active")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.ENOENT) {
			return errors.New("existing updater socket cannot be verified")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(path)
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	if e.Profile.CoreUID < 0 || e.Profile.CoreUID > 2147483647 {
		return errors.New("invalid registered core UID")
	}
	if err = os.Chown(path, e.Profile.CoreUID, -1); err != nil {
		return err
	}
	var busy atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("GET /host-placement", func(w http.ResponseWriter, r *http.Request) {
		worker, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", "/run/nahan-host-placement/placement.sock")
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(worker, "GET", "http://localhost/v1/placement?coreId="+e.Profile.CoreID, nil)
		if err != nil {
			http.Error(w, "placement unavailable", 503)
			return
		}
		response, err := client.Do(req)
		if err != nil {
			http.Error(w, "placement unavailable", 503)
			return
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			http.Error(w, "placement unavailable", 503)
			return
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 2048))
		if err != nil {
			http.Error(w, "placement unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		s, err := e.State()
		if err != nil {
			http.Error(w, "journal unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(s)
	})
	mux.HandleFunc("GET /installed", func(w http.ResponseWriter, r *http.Request) {
		s, err := e.Installed()
		if err != nil {
			http.Error(w, "rollback checkpoint unavailable", 409)
			return
		}
		json.NewEncoder(w).Encode(s)
	})
	for _, action := range []string{"prepare", "apply", "rollback"} {
		mux.HandleFunc("POST /"+action, func(w http.ResponseWriter, r *http.Request) {
			var request Request
			decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&request) != nil || !UUIDPattern.MatchString(request.ID) || !VersionPattern.MatchString(request.Version) || !DigestPattern.MatchString(request.ExpectedDigest) || request.ExpectedRevision < 0 || (request.JobID != "" && !UUIDPattern.MatchString(request.JobID)) {
				http.Error(w, "invalid update request", 400)
				return
			}
			if action != "prepare" && !request.Acknowledged {
				http.Error(w, "restart acknowledgement required", 400)
				return
			}
			if !busy.CompareAndSwap(false, true) {
				http.Error(w, "updater busy", 409)
				return
			}
			if err := Atomic(filepath.Join(e.Profile.StateDir, "pending.json"), map[string]any{"action": action, "request": request}); err != nil {
				busy.Store(false)
				http.Error(w, "journal unavailable", 503)
				return
			}
			go func() {
				defer busy.Store(false)
				worker, cancel := context.WithTimeout(ctx, 240*time.Second)
				defer cancel()
				var state Status
				var err error
				switch action {
				case "prepare":
					state, err = e.Prepare(worker, request)
				case "apply":
					state, err = e.Apply(worker, request)
				case "rollback":
					state, err = e.Rollback(worker, request)
				}
				if err != nil && state.Stage != "rolled_back" {
					if state.ID == request.ID {
						state.Error = "update_failed"
						e.save(&state, "failed")
					}
					failure := Status{ID: request.ID, Stage: "failed", Version: request.Version, UpdatedAt: time.Now().Unix(), Error: "update_failed"}
					Atomic(filepath.Join(e.Profile.StateDir, "failure.json"), failure)
				}
				reportContext, reportCancel := context.WithTimeout(ctx, 2*time.Minute)
				defer reportCancel()
				e.report(reportContext, request, state, err == nil)
			}()
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
		})
	}
	mux.HandleFunc("GET /failure", func(w http.ResponseWriter, r *http.Request) {
		var s Status
		data, err := os.ReadFile(filepath.Join(e.Profile.StateDir, "failure.json"))
		if err == nil {
			json.Unmarshal(data, &s)
		}
		json.NewEncoder(w).Encode(s)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096}
	go func() { <-ctx.Done(); server.Close() }()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func Call(ctx context.Context, coreID, method, action string, body any, out any) error {
	if !UUIDPattern.MatchString(coreID) {
		return errors.New("invalid updater identity")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", Socket(coreID))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost/"+action, reader)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("local updater unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 202 {
		return errors.New("local updater refused request")
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(out)
	}
	return nil
}
