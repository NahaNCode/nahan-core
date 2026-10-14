package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/NahaNCode/nahan-core/utility/paneltls"
	"github.com/xtls/xray-core/core"
	"golang.org/x/mod/semver"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// An existing core may use a local control proxy; never import its remote credentials.
func LocalPanelProxy(address string) (*url.URL, error) {
	if address == "" {
		return nil, nil
	}
	u, err := url.Parse(address)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Port() == "" || (u.Scheme != "http" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
		return nil, errors.New("updater proxy must be an unauthenticated loopback endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("updater proxy must be loopback")
	}
	return u, nil
}

func (e *Engine) panel(ctx context.Context, path string, body any) error {
	return e.panelRequest(ctx, "POST", path, body, nil)
}
func (e *Engine) panelRequest(ctx context.Context, method, path string, body any, out any) error {
	if e.Profile.PanelURL == "" || e.Profile.KeyFile == "" {
		return errors.New("updater reporting is not registered")
	}
	fd, err := syscall.Open(e.Profile.KeyFile, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("updater credential unavailable")
	}
	file := os.NewFile(uintptr(fd), "credential")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 256 {
		return errors.New("unsafe updater credential")
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, "\r\n") {
		return errors.New("invalid updater credential")
	}
	transport, err := paneltls.Transport(e.Profile.PanelURL, e.Profile.CAFile, e.Profile.ServerName)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	if e.Profile.PanelProxy != "" {
		proxy, err := LocalPanelProxy(e.Profile.PanelProxy)
		if err != nil {
			return err
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(e.Profile.PanelURL, "/")+"/api/core/v1/cores/"+e.Profile.CoreID+"/"+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Nahan-Egress-Runtime", "2")
	if e.Profile.ServerName != "" {
		request.Host = e.Profile.ServerName
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("updater report unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("updater report refused")
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out)
	}
	return nil
}
func (e *Engine) controlRevision(ctx context.Context, expected int64) (int64, error) {
	if e.Profile.PanelURL == "" {
		return expected, nil
	}
	var manifest struct {
		Revision int64 `json:"revision"`
	}
	if err := e.panelRequest(ctx, "GET", "manifest", nil, &manifest); err != nil {
		return 0, err
	}
	if expected > 0 && manifest.Revision != expected {
		return 0, errors.New("core manifest changed after preparation")
	}
	return manifest.Revision, nil
}
func (e *Engine) canRollback(ctx context.Context, version string) error {
	if semver.Compare(version, "v1.6.0") >= 0 || version == "" {
		return nil
	}
	path := filepath.Join(filepath.Dir(e.Profile.KeyFile), "egress-destination-principals", "retired.bin")
	if _, err := os.Stat(path); err == nil {
		return errors.New("the credential journal requires the current runtime")
	}
	if e.Profile.PanelURL == "" {
		return nil
	}
	var response struct {
		Desired *struct {
			PlanJSON string `json:"planJson"`
		} `json:"desired"`
	}
	if err := e.panelRequest(ctx, "GET", "egress", nil, &response); err != nil {
		return err
	}
	if response.Desired == nil {
		return nil
	}
	var plan struct {
		Profiles []struct {
			External json.RawMessage `json:"external"`
		} `json:"profiles"`
	}
	if json.Unmarshal([]byte(response.Desired.PlanJSON), &plan) != nil {
		return errors.New("rollback compatibility unavailable")
	}
	for _, p := range plan.Profiles {
		if len(p.External) > 0 && string(p.External) != "null" {
			return errors.New("personal outbound publication requires the current runtime")
		}
	}
	return nil
}
func (e *Engine) report(ctx context.Context, request Request, state Status, success bool) {
	if request.JobID == "" || !UUIDPattern.MatchString(request.JobID) {
		return
	}
	result := map[string]any{"valid": success, "code": "", "engineVersion": core.Version()}
	if success {
		result["digest"] = state.Digest
	} else {
		result["code"] = "upgrade_failed"
	}
	for ctx.Err() == nil {
		if e.panel(ctx, "jobs/"+request.JobID+"/result", result) == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	if state.Stage != "done" && state.Stage != "rolled_back" {
		return
	}
	digest, err := e.running(ctx)
	if err != nil {
		return
	}
	version := state.Version
	if state.Stage == "rolled_back" {
		version = state.PreviousVersion
	}
	body := map[string]any{"operationId": request.ID, "digest": digest, "version": version}
	for ctx.Err() == nil {
		if e.panel(ctx, "updates/runtime", body) == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}
