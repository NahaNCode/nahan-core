package entryprofile

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSecretTransfer(t *testing.T) {
	const source = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const target = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	const original = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	public := base64.StdEncoding.EncodeToString(der)
	for _, kind := range []string{"reality-key", "tls-certificate", "shadowsocks-password"} {
		t.Run(kind, func(t *testing.T) {
			src, dst := t.TempDir(), t.TempDir()
			name := "example.com"
			if kind == "shadowsocks-password" {
				name = "2022-blake3-aes-128-gcm"
			}
			meta, err := GenerateSecret(src, source, original, kind, name)
			if err != nil {
				t.Fatal(err)
			}
			scope := SecretTransferScope{source, target, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "ffffffff-ffff-4fff-8fff-ffffffffffff", 1, meta["reference"].(string), kind, time.Now().Unix() + 300}
			before, _ := os.ReadFile(filepath.Join(src, original+".json"))
			sealed, err := ExportSecret(src, source, scope.ExportID, public, scope)
			if err != nil {
				t.Fatal(err)
			}
			copied, err := ImportSecret(dst, target, scope.ImportID, key, scope, sealed)
			if err != nil {
				t.Fatal(err)
			}
			if copied["reference"] != "secret://core/"+target+"/"+scope.ImportID {
				t.Fatal("wrong target reference")
			}
			if _, err = ImportSecret(dst, target, scope.ImportID, key, scope, sealed); err != nil {
				t.Fatal("retry not idempotent", err)
			}
			after, _ := os.ReadFile(filepath.Join(dst, scope.ImportID+".json"))
			if string(before) != string(after) {
				t.Fatal("secret identity changed")
			}
			still, _ := os.ReadFile(filepath.Join(src, original+".json"))
			if string(before) != string(still) {
				t.Fatal("source mutated")
			}
			info, _ := os.Stat(filepath.Join(dst, scope.ImportID+".json"))
			if info.Mode().Perm() != 0600 {
				t.Fatal("unsafe target permissions")
			}
			publicJSON, _ := json.Marshal(copied)
			var secret StoredSecret
			_ = json.Unmarshal(before, &secret)
			if kind == "reality-key" && copied["publicKey"] != meta["publicKey"] {
				t.Fatal("public key changed")
			}
			var exposed map[string]any
			_ = json.Unmarshal(publicJSON, &exposed)
			if exposed["privateKey"] != nil || exposed["password"] != nil {
				t.Fatal("private metadata leaked")
			}
			bad := scope
			bad.Revision++
			if _, err = ImportSecret(t.TempDir(), target, bad.ImportID, key, bad, sealed); err == nil {
				t.Fatal("revision replay accepted")
			}
			bad = scope
			bad.ExpiresAt = time.Now().Unix() - 1
			if _, err = ImportSecret(t.TempDir(), target, bad.ImportID, key, bad, sealed); err == nil {
				t.Fatal("expired transfer accepted")
			}
			if _, err = ImportSecret(t.TempDir(), source, scope.ImportID, key, scope, sealed); err == nil {
				t.Fatal("wrong core accepted")
			}
			if _, err = ExportSecret(src, target, scope.ExportID, public, scope); err == nil {
				t.Fatal("wrong exporter accepted")
			}
			badSeal := sealed
			badSeal.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 12))
			if _, err = ImportSecret(t.TempDir(), target, scope.ImportID, key, scope, badSeal); err == nil {
				t.Fatal("tampering accepted")
			}
			collision := t.TempDir()
			if err = os.Symlink(filepath.Join(src, original+".json"), filepath.Join(collision, scope.ImportID+".json")); err != nil {
				t.Fatal(err)
			}
			if _, err = ImportSecret(collision, target, scope.ImportID, key, scope, sealed); err == nil {
				t.Fatal("symlink accepted")
			}
		})
	}
}
