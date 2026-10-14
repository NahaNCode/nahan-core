package egress

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/utility/entryprofile"
)

func TestExternalImportIsRecipientScopedEncryptedImmutableAndRestorable(t *testing.T) {
	const core = "11111111-1111-4111-8111-111111111111"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	credential, err := NewPrincipalCredential("vless", "")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": 12345, "users": []any{map[string]any{"id": credential.ID, "encryption": "none"}}}}}})
	hash := sha256.Sum256(data)
	scope := ExternalScope{ID: "22222222-2222-4222-8222-222222222222", CoreID: core, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	label, _ := scope.Label()
	sealed, err := entryprofile.Seal(data, base64.StdEncoding.EncodeToString(public), label)
	if err != nil {
		t.Fatal(err)
	}
	request := ExternalImport{Scope: scope, Digest: hex.EncodeToString(hash[:]), Protocol: "vless", Envelope: sealed}
	directory := filepath.Join(t.TempDir(), "private")
	secret := strings.Repeat("x", 64)
	if err = ImportExternal(directory, core, secret, key, request); err != nil {
		t.Fatal(err)
	}
	if err = ImportExternal(directory, core, secret, key, request); err != nil {
		t.Fatal("idempotent retry failed", err)
	}
	stored, err := os.ReadFile(filepath.Join(directory, scope.ID+".bin"))
	if err != nil || strings.Contains(string(stored), credential.ID) {
		t.Fatal("plaintext credential on disk", err)
	}
	binding := ExternalBinding{ID: scope.ID, Digest: request.Digest, Protocol: "vless"}
	restored, err := ReadExternal(directory, core, secret, binding)
	if err != nil || string(restored) != string(data) {
		t.Fatal("restart restoration failed", err)
	}
	bad := request
	bad.Scope.CoreID = "33333333-3333-4333-8333-333333333333"
	if ImportExternal(directory, core, secret, key, bad) == nil {
		t.Fatal("cross-core import accepted")
	}
	bad = request
	bad.Scope.ID = "44444444-4444-4444-8444-444444444444"
	if ImportExternal(directory, core, secret, key, bad) == nil {
		t.Fatal("scope tampering accepted")
	}
	bad = request
	bad.Digest = strings.Repeat("0", 64)
	if ImportExternal(directory, core, secret, key, bad) == nil {
		t.Fatal("digest tampering accepted")
	}
	if _, err = ReadExternal(directory, core, strings.Repeat("y", 64), binding); err == nil {
		t.Fatal("wrong storage key accepted")
	}
}

func TestExternalImportRejectsChainingLocalFilesAndUnverifiedTLS(t *testing.T) {
	for _, data := range []string{
		`{"protocol":"freedom","settings":{}}`,
		`{"protocol":"trojan","proxySettings":{"tag":"other"}}`,
		`{"protocol":"trojan","streamSettings":{"tlsSettings":{"allowInsecure":true}}}`,
		`{"protocol":"trojan","streamSettings":{"tlsSettings":{"certificates":[{"keyFile":"/private/key"}]}}}`,
		`{"protocol":"trojan","streamSettings":{"sockopt":{"dialerProxy":"other"}}}`,
		`{"protocol":"trojan","tag":"caller-owned"}`,
	} {
		if _, err := ValidateExternal([]byte(data)); err == nil {
			t.Fatal("unsafe outbound accepted")
		}
	}
}
