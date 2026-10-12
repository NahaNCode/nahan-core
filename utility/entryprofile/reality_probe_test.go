package entryprofile

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestRealityProbeSkipsOtherSecurity(t *testing.T) {
	for _, input := range []string{`{"streamSettings":{"security":"tls"}}`, `{"inbound":{"streamSettings":{"security":"none"}}}`} {
		if code := ProbeReality(context.Background(), []byte(input)); code != "" {
			t.Fatal(code)
		}
	}
}
func TestRealityProbeRejectsInvalidConfiguration(t *testing.T) {
	if code := ProbeReality(context.Background(), []byte(`{"streamSettings":{"security":"reality","realitySettings":{}}}`)); code != "reality_probe_invalid" {
		t.Fatal(code)
	}
}
func TestRealityProbeLiveCover(t *testing.T) {
	host := os.Getenv("NAHAN_REALITY_TEST_COVER")
	if host == "" {
		t.Skip("network integration test requires NAHAN_REALITY_TEST_COVER")
	}
	dir := t.TempDir()
	metadata, err := GenerateSecret(dir, "4f579a80-1f43-4a7c-bda1-01dabc4e9ce1", "12345678-1234-1234-1234-123456789abc", "reality-key", "")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := json.Marshal(map[string]any{"streamSettings": map[string]any{"security": "reality", "realitySettings": map[string]any{"target": host + ":443", "serverNames": []string{host}, "privateKey": metadata["reference"], "shortIds": []any{metadata["shortId"]}}}})
	resolved, err := Resolve(p, dir, "4f579a80-1f43-4a7c-bda1-01dabc4e9ce1")
	if err != nil {
		t.Fatal(err)
	}
	code := ProbeReality(context.Background(), resolved)
	if host == "www.cloudflare.com" && code != "" {
		t.Fatalf("Cloudflare probe: %s", code)
	}
	if host == "www.microsoft.com" && code == "" {
		t.Fatal("incompatible cover unexpectedly passed")
	}
}
