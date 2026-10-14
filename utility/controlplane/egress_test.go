package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEgressExactDocumentValidationAndScopedReceipt(t *testing.T) {
	plan := `{"snapshot":{"revision":2,"leaseSeconds":30,"bindings":[]},"profiles":[]}`
	digest := sha256.Sum256([]byte(plan))
	document := EgressDocument{Revision: 2, Digest: hex.EncodeToString(digest[:]), PlanJSON: plan}
	if err := document.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*EgressDocument){func(d *EgressDocument) { d.Revision = 3 }, func(d *EgressDocument) { d.PlanJSON += " " }, func(d *EgressDocument) { d.Digest = "invalid" }} {
		bad := document
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("tampered egress document accepted")
		}
	}
	const coreID = "11111111-1111-4111-8111-111111111111"
	var received bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-key" || r.Header.Get("X-Nahan-Egress-Runtime") != "1" {
			t.Error("egress request scope missing")
		}
		if r.Method == "GET" {
			if r.URL.Path != "/api/core/v1/cores/"+coreID+"/egress" {
				t.Error("wrong egress endpoint")
			}
			json.NewEncoder(w).Encode(EgressControl{Desired: &document, Prepared: &document})
			return
		}
		if r.URL.Path != "/api/core/v1/cores/"+coreID+"/egress/receipt" {
			t.Error("wrong receipt endpoint")
		}
		var receipt struct {
			Phase    string
			Revision int64
			Digest   string
			Code     string
		}
		if json.NewDecoder(r.Body).Decode(&receipt) != nil || receipt.Phase != "prepared" || receipt.Revision != 2 || receipt.Digest != document.Digest || receipt.Code != "" {
			t.Error("receipt not bound to exact plan")
		}
		received = true
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client := &Client{Config: &Config{APIHost: server.URL, CoreID: coreID}, Key: "private-key", http: server.Client()}
	state, err := client.Egress(context.Background())
	if err != nil || state.Desired.Digest != document.Digest {
		t.Fatal("control document failed", err)
	}
	if err = client.EgressReceipt(context.Background(), "prepared", document, ""); err != nil || !received {
		t.Fatal("receipt failed", err)
	}
}
