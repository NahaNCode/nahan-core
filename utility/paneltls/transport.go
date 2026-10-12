package paneltls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
)

// Only loopback HTTP is accepted; remote management always verifies TLS identity.
func Transport(address, caFile, serverName string) (*http.Transport, error) {
	u, err := url.Parse(address)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid panel URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, fmt.Errorf("remote panel requires verified TLS")
		}
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read panel CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("invalid panel CA")
		}
		config.RootCAs = roots
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = config
	return t, nil
}
