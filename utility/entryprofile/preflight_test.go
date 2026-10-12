package entryprofile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
)

const valid = `{"protocol":"vless","listen":"127.0.0.1","port":11245,"settings":{"decryption":"none","clients":[]},"streamSettings":{"network":"websocket","security":"none","wsSettings":{"path":"/advanced","headers":{"Host":"localhost"},"heartbeatPeriod":15},"sockopt":{"tcpKeepAliveIdle":30}},"sniffing":{"enabled":true,"routeOnly":true,"destOverride":["http","tls"]}}`

func TestAdvancedProfileBuildsWithoutBinding(t *testing.T) {
	result := Preflight([]byte(valid))
	if !result.Valid || len(result.Digest) != 64 || result.Stage != "built" {
		t.Fatalf("unexpected result: %+v", result)
	}
	result2 := Preflight([]byte("  " + valid))
	if result.Digest != result2.Digest {
		t.Fatal("digest depends on whitespace")
	}
}
func TestEnvelopeAndEngineVersion(t *testing.T) {
	document := map[string]any{"schemaVersion": 2, "engineVersion": core.Version(), "inbound": json.RawMessage(valid)}
	data, _ := json.Marshal(document)
	if !Preflight(data).Valid {
		t.Fatal("valid envelope rejected")
	}
	document["engineVersion"] = "wrong"
	data, _ = json.Marshal(document)
	if Preflight(data).Code != "engine_mismatch" {
		t.Fatal("wrong engine accepted")
	}
}

func TestUnknownProtocolSettingAndFractionalIntegerRejected(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(valid, `"decryption":"none"`, `"decryption":"none","unknownSetting":true`, 1),
		strings.Replace(valid, `"tcpKeepAliveIdle":30`, `"tcpKeepAliveIdle":30.5`, 1),
	} {
		if result := Preflight([]byte(raw)); result.Valid || result.Code != "invalid_field" {
			t.Fatalf("invalid schema accepted: %+v", result)
		}
	}
}

func TestDuplicatePropertiesAreRejected(t *testing.T) {
	raw := strings.Replace(valid, `"decryption":"none"`, `"decryption":"bad","decryption":"none"`, 1)
	if result := Preflight([]byte(raw)); result.Valid || result.Code != "invalid_or_duplicate_json" {
		t.Fatalf("ambiguous JSON accepted: %+v", result)
	}
}

func TestXHTTPAndGRPCAdvancedFieldsBuild(t *testing.T) {
	for _, transport := range []string{
		`{"network":"xhttp","security":"none","xhttpSettings":{"path":"/advanced","mode":"auto","scMaxEachPostBytes":"1000000-2000000"},"sockopt":{"tcpKeepAliveIdle":30}}`,
		`{"network":"grpc","security":"none","grpcSettings":{"serviceName":"advanced","idle_timeout":60}}`,
	} {
		var profile map[string]json.RawMessage
		if err := json.Unmarshal([]byte(valid), &profile); err != nil {
			t.Fatal(err)
		}
		profile["streamSettings"] = json.RawMessage(transport)
		raw, _ := json.Marshal(profile)
		if result := Preflight(raw); !result.Valid {
			t.Fatalf("valid transport rejected: %+v", result)
		}
	}
}
func TestUnsafeOrIncompleteInputRejected(t *testing.T) {
	for _, data := range []string{"{}", "{", valid + "{}", strings.Repeat(" ", MaxBytes+1), strings.Replace(valid, `"port":11245`, `"typo":11245`, 1), strings.Replace(valid, `"heartbeatPeriod":15`, `"heartbeatPeriod":15,"badOption":true`, 1), strings.Replace(valid, `"decryption":"none"`, `"decryption":"secret://lab/decryption"`, 1)} {
		if result := Preflight([]byte(data)); result.Valid {
			t.Fatal("invalid input accepted")
		}
	}
}
func TestEngineErrorDoesNotExposeSensitiveValues(t *testing.T) {
	raw := strings.Replace(valid, `"decryption":"none"`, `"decryption":"private-sensitive-value"`, 1)
	result := Preflight([]byte(raw))
	data, _ := json.Marshal(result)
	if result.Valid || result.Code != "engine_rejected" || strings.Contains(string(data), "private-sensitive-value") {
		t.Fatal("unsafe error result")
	}
}
