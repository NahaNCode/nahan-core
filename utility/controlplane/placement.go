package controlplane

import (
	"context"
	"encoding/json"
	updater "github.com/NahaNCode/nahan-core/utility/update"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"
)

type HostPlacement struct {
	HostID    string `json:"hostId"`
	CoreID    string `json:"coreId"`
	IssuedAt  int64  `json:"issuedAt"`
	Signature string `json:"signature"`
}

func (c *Client) hostPlacement(ctx context.Context) *HostPlacement {
	path := c.Config.HostSocket
	if path == "" {
		path = "/run/nahan-host-placement/placement.sock"
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return c.proxyPlacement(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/v1/placement?coreId="+url.QueryEscape(c.Config.CoreID), nil)
	if err != nil {
		return nil
	}
	res, err := client.Do(req)
	if err != nil {
		return c.proxyPlacement(ctx)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil
	}
	var proof HostPlacement
	if json.NewDecoder(io.LimitReader(res.Body, 2048)).Decode(&proof) != nil || proof.CoreID != c.Config.CoreID || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(proof.HostID) || len(proof.Signature) != 88 || proof.IssuedAt < time.Now().Unix()-60 || proof.IssuedAt > time.Now().Unix()+5 {
		return nil
	}
	return &proof
}
func (c *Client) proxyPlacement(ctx context.Context) *HostPlacement {
	worker, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var proof HostPlacement
	if updater.Call(worker, c.Config.CoreID, "GET", "host-placement", nil, &proof) != nil || proof.CoreID != c.Config.CoreID || !updater.UUIDPattern.MatchString(proof.HostID) || proof.IssuedAt < time.Now().Unix()-60 || proof.IssuedAt > time.Now().Unix()+5 || len(proof.Signature) != 88 {
		return nil
	}
	return &proof
}
