package controlplane

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/NahaNCode/nahan-core/utility/paneltls"
	xproxy "golang.org/x/net/proxy"
)

// The core credential remains inside verified end-to-end TLS, including while
// traversing the selected destination. No plaintext management probe is allowed.
func (c *Client) ProbeViaSOCKS(ctx context.Context, address, user, password string) error {
	panel, err := url.Parse(c.Config.APIHost)
	if err != nil || panel.Scheme != "https" {
		return errors.New("egress path probe requires verified panel TLS")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || user == "" || len(password) < 32 {
		return errors.New("invalid local probe transport")
	}
	t, err := paneltls.Transport(c.Config.APIHost, c.Config.CAFile, c.Config.ServerName)
	if err != nil {
		return err
	}
	defer t.CloseIdleConnections()
	dialer, err := xproxy.SOCKS5("tcp", address, &xproxy.Auth{User: user, Password: password}, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return err
	}
	d, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return errors.New("probe transport has no cancellation support")
	}
	t.Proxy = nil
	t.DialContext = d.DialContext
	probe := &Client{Config: c.Config, Key: c.Key, http: &http.Client{Transport: t, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	_, err = probe.Manifest(ctx)
	return err
}
