package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutingPolicyJobsAndHeartbeat(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rejected"}[reject], func(t *testing.T) {
			completions := 0
			refreshed := 0
			applied := 0
			heartbeat := false
			report := map[string]any{"runtimeVersion": 1, "enabled": !reject}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/jobs") {
					w.Write([]byte(`[{"id":"7780f5ce-6e8d-44c7-8830-40d7570bc17b","kind":"routing-policy-inspect","payload":{}},{"id":"82d7893a-9423-4d6f-b8eb-5198f25c798e","kind":"routing-policy-apply","payload":{"acknowledged":true}}]`))
					return
				}
				var data map[string]any
				if json.NewDecoder(r.Body).Decode(&data) != nil {
					t.Error("invalid JSON")
					return
				}
				if strings.HasSuffix(r.URL.Path, "/heartbeat") {
					heartbeat = data["routingPolicy"] != nil
					return
				}
				completions++
				if data["routingPolicy"] == nil {
					t.Error("missing report")
				}
				if strings.Contains(r.URL.Path, "82d7893a") {
					if data["valid"] == reject {
						t.Error("wrong completion validity")
					}
					if reject && data["code"] != "routing_policy_rejected" {
						t.Error("wrong safe code")
					}
				}
			}))
			defer server.Close()
			client := &Client{Config: &Config{APIHost: server.URL, CoreID: "75667842-8144-45a1-b68d-b25d7c617b4a"}, http: server.Client(), RoutingPolicyReport: func() any { return report }, RoutingPolicyRefresh: func() { refreshed++ }, RoutingPolicyApply: func(input json.RawMessage, id string) (any, error) {
				applied++
				if reject {
					return report, errors.New("private detail")
				}
				return report, nil
			}}
			if err := client.ProcessJobs(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := client.Heartbeat(context.Background(), "test", &Manifest{Revision: 1}, ""); err != nil {
				t.Fatal(err)
			}
			if completions != 2 || applied != 1 || refreshed < 3 || !heartbeat {
				t.Fatal("callbacks/report not integrated")
			}
		})
	}
}
