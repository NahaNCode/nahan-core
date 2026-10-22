package controlplane

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestManagementHealthBoundedAndSeparateFromApply(t *testing.T) {
	c := &Client{}
	for i := 0; i < 10000; i++ {
		c.management.record(fmt.Sprintf("jobs/private-id-%d/result", i), time.Now(), &StatusError{Code: 503})
	}
	status := c.ManagementStatus()
	s := status["jobs"]
	if len(status) != 1 || s.Failures != 10000 || s.Suppressed != 9999 || s.LastCode != "http_503" {
		t.Fatal("unbounded or inaccurate health", status)
	}
	c.management.record("heartbeat", time.Now(), nil)
	c.management.record("jobs", time.Now(), nil)
	status = c.ManagementStatus()
	if status["heartbeat"].Failures != 0 || status["jobs"].ConsecutiveFailures != 0 || status["jobs"].LastFailure.IsZero() {
		t.Fatal("lane failure/recovery lost", status)
	}
	delete(status, "jobs")
	if len(c.ManagementStatus()) != 2 {
		t.Fatal("mutable diagnostics snapshot")
	}
	c.management.record("private-unknown-resource", time.Now(), context.Canceled)
	if len(c.ManagementStatus()) != 2 {
		t.Fatal("shutdown counted as incident")
	}
}

func TestHeartbeatSnapshotDoesNotReadMutableCallbacks(t *testing.T) {
	c := &Client{Config: &Config{HasCustomRouting: true}}
	manifest := &Manifest{Revision: 4}
	manifest.Nodes = append(manifest.Nodes, struct {
		ID int `json:"id"`
	}{ID: 123})
	c.RoutingPolicyReport = func() any { return map[string]any{"enabled": true} }
	snapshot := c.CaptureHeartbeat(manifest, "configuration applying")
	manifest.Nodes[0].ID = 999
	c.Config.HasCustomRouting = false
	if snapshot.NodeIDs[0] != 123 || !snapshot.CustomRouting || snapshot.LastError != "configuration applying" {
		t.Fatal("heartbeat aliases live state")
	}
}
