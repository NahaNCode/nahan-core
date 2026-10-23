package paneltls

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestFailoverDiagnosesEachRouteAndRecoversPrimary(t *testing.T) {
	primaryHealthy := false
	f := &failover{routeTimeout: time.Second, routes: []http.RoundTripper{
		roundTripFunc(func(*http.Request) (*http.Response, error) {
			if primaryHealthy {
				return reply(200), nil
			}
			return nil, &net.DNSError{Err: "private diagnostic", Name: "must-not-be-retained"}
		}),
		roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded }),
		roundTripFunc(func(*http.Request) (*http.Response, error) { return reply(200), nil }),
	}}
	request, _ := http.NewRequest("GET", "https://pwaapi.nahanvpn.com/api/core/v1/nodes/1/server", nil)
	response, err := f.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	status := f.RouteObservations()
	if len(status) != 3 || status["route-primary"].LastCode != "dns_failure" || status["route-direct-1"].LastCode != "timeout" || status["route-direct-2"].Failures != 0 {
		t.Fatal("route cause lost", status)
	}
	primaryHealthy = true
	f.mu.Lock()
	f.retryPrimary = time.Now().Add(-time.Second)
	f.mu.Unlock()
	response, err = f.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	status = f.RouteObservations()
	if status["route-primary"].Attempts != 2 || status["route-primary"].ConsecutiveFailures != 0 || status["route-primary"].LastFailure.IsZero() {
		t.Fatal("primary recovery/history lost", status)
	}
}
