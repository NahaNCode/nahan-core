package paneltls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// This public trust anchor grants no enrollment or API privileges.
//
//go:embed control-root.pem
var controlRoot []byte

const ControlServerName = "control.nahan.internal"
const RequestTimeout = 30 * time.Second

var uuidPart = `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`
var coreRoute = regexp.MustCompile(`^/api/core/v1/cores/` + uuidPart + `/(manifest|heartbeat|jobs|jobs/` + uuidPart + `/result|egress|egress/(identity|credentials|receipt|health)|connection-policy|connection-policy/receipt|exit-routing|exit-routing/(report|receipt)|updates/runtime)$`)
var nodeRoute = regexp.MustCompile(`^/api/core/v1/nodes/[1-9][0-9]*/(server|subscriptions|heartbeat|traffic|onlineip|device-leases)$`)

type failover struct {
	routes       []http.RoundTripper
	mu           sync.Mutex
	preferred    int
	retryPrimary time.Time
	routeTimeout time.Duration
	observations [3]RouteObservation
}

// WithFailover is deliberately limited to the official panel and exact core APIs.
// A custom DialContext (including SOCKS probes) is preserved for every route.
func WithFailover(address string, primary *http.Transport) (http.RoundTripper, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host != "pwaapi.nahanvpn.com" || (u.Path != "" && u.Path != "/") {
		return primary, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(controlRoot) {
		return nil, errors.New("invalid control trust root")
	}
	primary.Proxy = nil
	primary.ForceAttemptHTTP2 = false
	primary.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	primary.TLSClientConfig.NextProtos = []string{"http/1.1"}
	routes := []http.RoundTripper{primary}
	dial := primary.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 4 * time.Second}).DialContext
	}
	for _, ip := range []string{"152.53.172.146", "152.53.176.197"} {
		target := net.JoinHostPort(ip, "443")
		tr := primary.Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: ControlServerName, NextProtos: []string{"http/1.1"}}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) { return dial(ctx, network, target) }
		routes = append(routes, tr)
	}
	return &failover{routes: routes, routeTimeout: 8 * time.Second}, nil
}

func replaySafe(r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	if r.Method != http.MethodPost {
		return false
	}
	p := r.URL.Path
	if strings.HasSuffix(p, "/traffic") {
		return r.Header.Get("Idempotency-Key") != ""
	}
	// These endpoints replace observations, or acknowledge an exact immutable ID.
	return strings.HasSuffix(p, "/heartbeat") || strings.HasSuffix(p, "/onlineip") || strings.HasSuffix(p, "/egress/health") || strings.HasSuffix(p, "/updates/runtime")
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (f *failover) CloseIdleConnections() {
	for _, route := range f.routes {
		if closer, ok := route.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func (b *cancelBody) Close() error { err := b.ReadCloser.Close(); b.cancel(); return err }

func (f *failover) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "pwaapi.nahanvpn.com" || r.URL.RawQuery != "" || r.URL.RawPath != "" || (!coreRoute.MatchString(r.URL.Path) && !nodeRoute.MatchString(r.URL.Path)) {
		return f.routes[0].RoundTrip(r)
	}
	f.mu.Lock()
	first := 0
	if f.preferred > 0 && time.Now().Before(f.retryPrimary) {
		first = f.preferred
	}
	f.mu.Unlock()
	order := []int{first}
	for i := range f.routes {
		if i != first {
			order = append(order, i)
		}
	}
	retry := replaySafe(r) && (r.Body == nil || r.Body == http.NoBody || r.GetBody != nil)
	if !retry {
		order = order[:1]
	}
	var last error
	for n, index := range order {
		if r.Context().Err() != nil {
			return nil, r.Context().Err()
		}
		ctx, cancel := context.WithTimeout(r.Context(), f.routeTimeout)
		req := r.Clone(ctx)
		if n > 0 && r.GetBody != nil {
			var err error
			req.Body, err = r.GetBody()
			if err != nil {
				cancel()
				return nil, err
			}
		}
		if index > 0 {
			req.Host = ControlServerName
		}
		started := time.Now()
		response, err := f.routes[index].RoundTrip(req)
		f.observe(index, started, err, response)
		gateway := response != nil && (response.StatusCode == 502 || response.StatusCode == 503 || response.StatusCode == 504)
		if err != nil || gateway {
			if response != nil && !gateway {
				response.Body.Close()
			}
			if gateway && n == len(order)-1 {
				response.Body = &cancelBody{response.Body, cancel}
				return response, nil
			}
			if gateway {
				response.Body.Close()
			}
			cancel()
			last = errors.New("panel connection failed on verified route")
			if err != nil {
				last = fmt.Errorf("panel connection failed on verified route: %w", err)
			}
			continue
		}
		// Auth, conflicts, redirects and other application responses are terminal.
		if response.StatusCode >= 200 && response.StatusCode < 400 {
			f.mu.Lock()
			changed := f.preferred != index
			f.preferred = index
			if index > 0 && (changed || !time.Now().Before(f.retryPrimary)) {
				f.retryPrimary = time.Now().Add(time.Minute)
			}
			f.mu.Unlock()
		}
		response.Body = &cancelBody{response.Body, cancel}
		return response, nil
	}
	return nil, last
}
