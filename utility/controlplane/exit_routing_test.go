package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExitRoutingReportAndExactRootDocument(t *testing.T) {
	plan := `{"revision":2,"leaseSeconds":30,"rules":[]}`
	digest := sha256.Sum256([]byte(plan))
	original := EgressDocument{Revision: 2, Digest: hex.EncodeToString(digest[:]), PlanJSON: plan}
	for _, test := range []struct {
		name   string
		change func(*EgressDocument)
		valid  bool
	}{
		{"valid", func(*EgressDocument) {}, true},
		{"wrong revision", func(d *EgressDocument) { d.Revision++ }, false},
		{"changed content", func(d *EgressDocument) { d.PlanJSON += " " }, false},
		{"invalid digest", func(d *EgressDocument) { d.Digest = "invalid" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := original
			test.change(&document)
			reported := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-key" {
					t.Error("missing core authentication")
				}
				if strings.HasSuffix(r.URL.Path, "/report") {
					var body struct {
						RuntimeVersion int
						IPs            []string
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.RuntimeVersion != 1 || len(body.IPs) != 1 || body.IPs[0] != "192.0.2.146" {
						t.Error("invalid inventory report")
					}
					reported = true
					w.Write([]byte(`{}`))
					return
				}
				if !reported {
					t.Error("document requested before inventory")
				}
				json.NewEncoder(w).Encode(document)
			}))
			defer server.Close()
			c := &Client{Config: &Config{APIHost: server.URL, CoreID: "11111111-1111-4111-8111-111111111111"}, Key: "test-key", http: server.Client()}
			got, err := c.ExitRouting(context.Background(), []string{"192.0.2.146"})
			if test.valid && (err != nil || got.Digest != original.Digest) {
				t.Fatal(err)
			}
			if !test.valid && err == nil {
				t.Fatal("tampered exit document accepted")
			}
		})
	}
}
