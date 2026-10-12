package nahan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManagedTCPOptionalHeader(t *testing.T) {
	for _, transport := range []string{"tcp", "raw"} {
		for _, header := range []string{"", `,"header":null`, `,"header":{"type":"none"}`, `,"header":{"type":"http","request":{"path":"/probe"}}`} {
			t.Run(transport+header, func(t *testing.T) {
				var config serverConfig
				payload := `{"server":{"type":"Vless","listeningport":"11243","listenip":"127.0.0.1","security":"none","networkSettings":{"transport":"` + transport + `"` + header + `}}}`
				if err := json.Unmarshal([]byte(payload), &config); err != nil {
					t.Fatal(err)
				}
				client := &APIClient{NodeID: 20000001}
				node, err := client.parseNodeResponse(&config)
				if err != nil {
					t.Fatal(err)
				}
				var parsed struct {
					Type string `json:"type"`
				}
				if err := json.Unmarshal(node.Header, &parsed); err != nil {
					t.Fatal(err)
				}
				want := "none"
				if strings.Contains(header, `"http"`) {
					want = "http"
				}
				if parsed.Type != want {
					t.Fatalf("header type %q, want %q", parsed.Type, want)
				}
			})
		}
	}
}
