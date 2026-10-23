package paneltls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

type RouteObservation struct {
	Attempts            uint64    `json:"attempts"`
	Failures            uint64    `json:"failures"`
	ConsecutiveFailures uint64    `json:"consecutiveFailures"`
	LastSuccess         time.Time `json:"lastSuccess"`
	LastFailure         time.Time `json:"lastFailure"`
	LastCode            string    `json:"lastCode"`
	DurationMS          int64     `json:"durationMs"`
}

func routeError(err error, response *http.Response) string {
	var dns *net.DNSError
	var verify *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.HostnameError
	var timeout net.Error
	switch {
	case errors.As(err, &dns):
		return "dns_failure"
	case errors.As(err, &verify), errors.As(err, &unknown), errors.As(err, &invalid):
		return "tls_identity_failure"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case err != nil:
		return "connection_failure"
	case response != nil && response.StatusCode >= 400:
		return fmt.Sprintf("http_%d", response.StatusCode)
	default:
		return ""
	}
}

func (f *failover) observe(index int, started time.Time, err error, response *http.Response) {
	if index >= len(f.observations) {
		return
	}
	code := routeError(err, response)
	if code == "canceled" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &f.observations[index]
	s.Attempts++
	s.DurationMS = time.Since(started).Milliseconds()
	if code == "" {
		s.LastSuccess = time.Now().UTC()
		s.ConsecutiveFailures = 0
	} else {
		s.Failures++
		s.ConsecutiveFailures++
		s.LastFailure = time.Now().UTC()
		s.LastCode = code
	}
}

func (f *failover) RouteObservations() map[string]RouteObservation {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]RouteObservation)
	for i, name := range []string{"route-primary", "route-direct-1", "route-direct-2"} {
		if i < len(f.routes) && f.observations[i].Attempts > 0 {
			out[name] = f.observations[i]
		}
	}
	return out
}
