package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/NahaNCode/nahan-core/utility/paneltls"
	log "github.com/sirupsen/logrus"
)

type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("control plane status %d", e.Code) }

type ManagementObservation struct {
	Attempts            uint64    `json:"attempts"`
	Failures            uint64    `json:"failures"`
	ConsecutiveFailures uint64    `json:"consecutiveFailures"`
	LastSuccess         time.Time `json:"lastSuccess"`
	LastFailure         time.Time `json:"lastFailure"`
	LastCode            string    `json:"lastCode"`
	DurationMS          int64     `json:"durationMs"`
	Suppressed          uint64    `json:"suppressed"`
	lastLog             time.Time
	degraded            bool
}

type managementHealth struct {
	mu    sync.Mutex
	lanes map[string]ManagementObservation
}

// A fixed vocabulary bounds memory and log cardinality; no URL, ID or secret is retained.
func managementLane(resource string) string {
	for _, prefix := range []string{"manifest", "heartbeat", "jobs", "egress", "exit-routing", "connection-policy", "updates"} {
		if resource == prefix || strings.HasPrefix(resource, prefix+"/") {
			return prefix
		}
	}
	return "other"
}

func managementError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrUnauthorized) {
		return "authentication_revoked"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	var status *StatusError
	if errors.As(err, &status) {
		return fmt.Sprintf("http_%d", status.Code)
	}
	return "transport_or_invalid_response"
}

func (h *managementHealth) record(resource string, started time.Time, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	now := time.Now().UTC()
	lane, code := managementLane(resource), managementError(err)
	h.mu.Lock()
	if h.lanes == nil {
		h.lanes = make(map[string]ManagementObservation)
	}
	s := h.lanes[lane]
	s.Attempts++
	s.DurationMS = time.Since(started).Milliseconds()
	if err == nil {
		s.LastSuccess, s.ConsecutiveFailures = now, 0
	} else {
		s.LastFailure, s.LastCode = now, code
		s.Failures++
		s.ConsecutiveFailures++
	}
	// At most one summary per lane per minute, including flapping/recovery.
	emit := (err != nil || s.degraded) && (s.lastLog.IsZero() || now.Sub(s.lastLog) >= time.Minute)
	if emit {
		s.lastLog = now
	} else if err != nil {
		s.Suppressed++
	}
	s.degraded = err != nil
	h.lanes[lane] = s
	h.mu.Unlock()
	if emit {
		fields := log.Fields{"lane": lane, "code": code, "failures": s.Failures, "suppressed": s.Suppressed}
		if err == nil {
			log.WithFields(fields).Info("Management request recovered")
		} else {
			log.WithFields(fields).Warn("Management request unavailable")
		}
	}
}

func (c *Client) ManagementStatus() map[string]ManagementObservation {
	h := &c.management
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]ManagementObservation, len(h.lanes))
	for name, observation := range h.lanes {
		out[name] = observation
	}
	if c.http != nil {
		if transport, ok := c.http.Transport.(interface {
			RouteObservations() map[string]paneltls.RouteObservation
		}); ok {
			for name, s := range transport.RouteObservations() {
				out[name] = ManagementObservation{Attempts: s.Attempts, Failures: s.Failures, ConsecutiveFailures: s.ConsecutiveFailures, LastSuccess: s.LastSuccess, LastFailure: s.LastFailure, LastCode: s.LastCode, DurationMS: s.DurationMS}
			}
		}
	}
	return out
}
