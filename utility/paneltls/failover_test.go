package paneltls

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const healthPath = "/api/core/v1/cores/11111111-1111-4111-8111-111111111111/egress/health"

func reply(code int) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}
}
func TestFailoverReplayAndStickyRecovery(t *testing.T) {
	var primary, direct atomic.Int32
	f := &failover{routeTimeout: time.Second}
	f.routes = []http.RoundTripper{
		roundTripFunc(func(r *http.Request) (*http.Response, error) { primary.Add(1); return reply(503), nil }),
		roundTripFunc(func(r *http.Request) (*http.Response, error) {
			direct.Add(1)
			b, _ := io.ReadAll(r.Body)
			if string(b) != `{"revision":1}` || r.Header.Get("Authorization") != "Bearer test" || r.Host != ControlServerName {
				t.Error("replay identity or payload changed")
			}
			return reply(200), nil
		}),
	}
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("POST", "https://pwaapi.nahanvpn.com"+healthPath, strings.NewReader(`{"revision":1}`))
		req.Header.Set("Authorization", "Bearer test")
		r, e := f.RoundTrip(req)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
	}
	if primary.Load() != 1 || direct.Load() != 3 {
		t.Fatalf("wrong preference %d %d", primary.Load(), direct.Load())
	}
	f.mu.Lock()
	f.retryPrimary = time.Now().Add(-time.Second)
	f.mu.Unlock()
	req, _ := http.NewRequest("POST", "https://pwaapi.nahanvpn.com"+healthPath, strings.NewReader(`{"revision":1}`))
	req.Header.Set("Authorization", "Bearer test")
	r, e := f.RoundTrip(req)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if primary.Load() != 2 {
		t.Fatal("public route never retried")
	}
}
func TestFailoverTerminalAndUnsafeRequests(t *testing.T) {
	for _, code := range []int{200, 301, 400, 401, 403, 409, 429, 500} {
		f := &failover{routeTimeout: time.Second, routes: []http.RoundTripper{roundTripFunc(func(*http.Request) (*http.Response, error) { return reply(code), nil }), roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Error("application status replayed")
			return reply(200), nil
		})}}
		req, _ := http.NewRequest("POST", "https://pwaapi.nahanvpn.com"+healthPath, strings.NewReader(`{}`))
		r, e := f.RoundTrip(req)
		if e != nil || r.StatusCode != code {
			t.Fatal("terminal status lost")
		}
		r.Body.Close()
	}
	for _, path := range []string{"/api/core/admin/cores", "/api/core/v1/nodes/1/traffic", "/api/core/v1/nodes/1/device-leases", "/api/core/v1/cores/11111111-1111-4111-8111-111111111111/jobs/22222222-2222-4222-8222-222222222222/result"} {
		f := &failover{routeTimeout: time.Second, routes: []http.RoundTripper{roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("ambiguous send") }), roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Error("unsafe request replayed")
			return reply(200), nil
		})}}
		req, _ := http.NewRequest("POST", "https://pwaapi.nahanvpn.com"+path, strings.NewReader(`{}`))
		if _, err := f.RoundTrip(req); err == nil {
			t.Fatal("failed write reported success")
		}
	}
}
func TestFailoverTimeoutCancellationAndIdempotentTraffic(t *testing.T) {
	var calls atomic.Int32
	f := &failover{routeTimeout: 10 * time.Millisecond, routes: []http.RoundTripper{roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() }), roundTripFunc(func(*http.Request) (*http.Response, error) { calls.Add(1); return reply(200), nil })}}
	req, _ := http.NewRequest("POST", "https://pwaapi.nahanvpn.com/api/core/v1/nodes/1/traffic", strings.NewReader(`{}`))
	req.Header.Set("Idempotency-Key", "same-report")
	r, e := f.RoundTrip(req)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if calls.Load() != 1 {
		t.Fatal("deduplicated report did not fall back")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ = http.NewRequestWithContext(ctx, "GET", "https://pwaapi.nahanvpn.com/api/core/v1/nodes/1/server", nil)
	if _, e = f.RoundTrip(req); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}
func TestFailoverPreservesProbeDialAndVerifiesPrivateCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted private TLS accepted") }))
	defer server.Close()
	var dials atomic.Int32
	tr, _ := Transport("https://pwaapi.nahanvpn.com", "", "")
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	wrapped, e := WithFailover("https://pwaapi.nahanvpn.com", tr)
	if e != nil {
		t.Fatal(e)
	}
	req, _ := http.NewRequest("GET", "https://pwaapi.nahanvpn.com/api/core/v1/nodes/1/server", nil)
	if _, e = wrapped.RoundTrip(req); e == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if dials.Load() != 3 {
		t.Fatalf("fallback bypassed probe dial: %d", dials.Load())
	}
	f := wrapped.(*failover)
	for _, route := range f.routes {
		tls := route.(*http.Transport).TLSClientConfig
		if tls.InsecureSkipVerify {
			t.Fatal("TLS disabled")
		}
	}
	other, _ := Transport("https://other.example", "", "")
	w, e := WithFailover("https://other.example", other)
	if e != nil || w != other {
		t.Fatal("custom panel inherited official trust")
	}
}
