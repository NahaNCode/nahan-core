package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"github.com/NahaNCode/nahan-core/utility/paneltls"
	updater "github.com/NahaNCode/nahan-core/utility/update"
	"github.com/xtls/xray-core/core"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type Config struct {
	AllowManagedEgress bool   `mapstructure:"AllowManagedEgress"`
	HostSocket         string `mapstructure:"HostSocket"`
	HasCustomRouting   bool   `mapstructure:"-"`
	APIHost            string `mapstructure:"ApiHost"`
	CoreID             string `mapstructure:"CoreID"`
	KeyFile            string `mapstructure:"KeyFile"`
	CAFile             string `mapstructure:"CAFile"`
	ServerName         string `mapstructure:"ServerName"`
}
type Manifest struct {
	Revision int64 `json:"revision"`
	Nodes    []struct {
		ID int `json:"id"`
	} `json:"nodes"`
}
type Client struct {
	PrincipalDurable   bool
	PrincipalProvision func(json.RawMessage, string) (entryprofile.SealedResult, error)
	SSTrial            func(json.RawMessage, string, string) (entryprofile.SealedResult, error)
	Config             *Config
	Key                string
	http               *http.Client
	preflight          egressPreflight
}

var ErrUnauthorized = errors.New("core authentication revoked")

func New(config *Config) (*Client, error) {
	if !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(config.CoreID) {
		return nil, fmt.Errorf("invalid core identity")
	}
	data, err := os.ReadFile(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read core key: %w", err)
	}
	info, err := os.Stat(config.KeyFile)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("core key must have owner-only permissions")
	}
	key := strings.TrimSpace(string(data))
	if len(key) < 32 || len(key) > 256 || strings.ContainsAny(key, "\r\n") {
		return nil, fmt.Errorf("invalid core key")
	}
	transport, err := paneltls.Transport(config.APIHost, config.CAFile, config.ServerName)
	if err != nil {
		return nil, err
	}
	return &Client{Config: config, Key: key, http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) request(ctx context.Context, method, resource string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Config.APIHost, "/")+"/api/core/v1/cores/"+c.Config.CoreID+"/"+resource, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	if c.Config.ServerName != "" {
		req.Host = c.Config.ServerName
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Nahan-Policy-Runtime", "2")
	req.Header.Set("X-Nahan-Egress-Runtime", "2")
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("control plane unavailable: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return ErrUnauthorized
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("control plane status %d", res.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
	}
	return nil
}
func (c *Client) Manifest(ctx context.Context) (*Manifest, error) {
	var manifest Manifest
	if err := c.request(ctx, "GET", "manifest", nil, &manifest); err != nil {
		return nil, err
	}
	if manifest.Revision < 1 {
		return nil, fmt.Errorf("invalid manifest revision")
	}
	seen := map[int]bool{}
	for _, node := range manifest.Nodes {
		if node.ID <= 0 || seen[node.ID] {
			return nil, fmt.Errorf("invalid manifest node")
		}
		seen[node.ID] = true
	}
	return &manifest, nil
}
func (c *Client) Heartbeat(ctx context.Context, version string, manifest *Manifest, lastError string) error {
	ids := make([]int, 0, len(manifest.Nodes))
	for _, node := range manifest.Nodes {
		ids = append(ids, node.ID)
	}
	err := c.request(ctx, "POST", "heartbeat", map[string]any{"runtimeArch": runtime.GOOS + "-" + runtime.GOARCH, "runtimeBuild": updater.RunningDigest(), "updateRuntimeVersion": boolRuntime(updater.Available(c.Config.CoreID)), "hostPlacement": c.hostPlacement(ctx), "version": version, "revision": manifest.Revision, "nodeIds": ids, "lastError": lastError, "entryRuntimeVersion": 1, "ssTestRuntimeVersion": 2,
		"xrayVersion": core.Version(), "migrationRuntimeVersion": 1, "customRoutingEnabled": c.Config.HasCustomRouting, "controlEndpoint": strings.TrimRight(c.Config.APIHost, "/") + "/api/core/v1/cores/" + c.Config.CoreID + "/heartbeat", "reportIntervalSeconds": 10}, nil)
	if err == nil && updater.Available(c.Config.CoreID) && lastError == "" {
		updater.Atomic(filepath.Join(filepath.Dir(c.Config.KeyFile), "update-heartbeat-"+c.Config.CoreID+".json"), updater.Receipt{CoreID: c.Config.CoreID, Revision: manifest.Revision, Digest: updater.RunningDigest(), Version: version, SeenAt: time.Now().Unix()})
	}
	return err
}
func boolRuntime(available bool) int {
	if available {
		return 1
	}
	return 0
}
