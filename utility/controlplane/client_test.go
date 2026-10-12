package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHeartbeatReportsEngineAndRealEndpoint(t *testing.T) {
	coreID := "11111111-1111-1111-1111-111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Fatal(err)
		}
		if data["xrayVersion"] == "" || data["xrayVersion"] == nil || data["reportIntervalSeconds"] != float64(10) {
			t.Error("missing actual runtime metadata")
		}
		if data["controlEndpoint"] != "http://"+r.Host+"/api/core/v1/cores/"+coreID+"/heartbeat" {
			t.Error("wrong control endpoint")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := &Client{Config: &Config{APIHost: server.URL, CoreID: coreID}, Key: "private-test-key", http: server.Client()}
	if err := client.Heartbeat(context.Background(), "1.5.0", &Manifest{Revision: 1}, ""); err != nil {
		t.Fatal(err)
	}
}

func TestManifestScopedAndValidated(t *testing.T) {
	key := filepath.Join(t.TempDir(), "core.key")
	if err := os.WriteFile(key, []byte("0123456789abcdef0123456789abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	coreID := "11111111-1111-1111-1111-111111111111"
	body := `{"revision":2,"nodes":[{"id":20000001}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer 0123456789abcdef0123456789abcdef" || r.URL.Path != "/api/core/v1/cores/"+coreID+"/manifest" {
			t.Error("wrong identity")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	defer server.Close()
	client, err := New(&Config{APIHost: server.URL, CoreID: coreID, KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := client.Manifest(context.Background())
	if err != nil || manifest.Revision != 2 || manifest.Nodes[0].ID != 20000001 {
		t.Fatal("manifest not read", err)
	}
	body = `{"revision":2,"nodes":[{"id":1},{"id":1}]}`
	if _, err := client.Manifest(context.Background()); err == nil {
		t.Fatal("duplicate nodes accepted")
	}
	body = `{"revision":0,"nodes":[]}`
	if _, err := client.Manifest(context.Background()); err == nil {
		t.Fatal("invalid revision accepted")
	}
}
