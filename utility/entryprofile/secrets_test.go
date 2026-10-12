package entryprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCore = "4f579a80-1f43-4a7c-bda1-01dabc4e9ce1"
const testSecret = "11111111-1111-4111-8111-111111111111"

func TestGeneratedSSSecretStaysPrivateAndCipherSized(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "chacha20-ietf-poly1305"} {
		directory := t.TempDir()
		first, err := GenerateSecret(directory, testCore, testSecret, "shadowsocks-password", method)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := readSecret(filepath.Join(directory, testSecret+".json"))
		if err != nil || stored.Password == "" {
			t.Fatal("missing SS secret")
		}
		result, _ := json.Marshal(first)
		if strings.Contains(string(result), stored.Password) || strings.Contains(string(result), "password") {
			t.Fatal("SS password leaked")
		}
		repeated, err := GenerateSecret(directory, testCore, testSecret, "shadowsocks-password", method)
		if err != nil || first["reference"] != repeated["reference"] {
			t.Fatal("generation not idempotent")
		}
		if _, err = GenerateSecret(directory, testCore, testSecret, "shadowsocks-password", "none"); err == nil {
			t.Fatal("cipher mismatch accepted")
		}
	}
}

func TestImportedShadowsocksSecretIsScopedAndPrivate(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, testSecret+".json")
	password := "AAAAAAAAAAAAAAAAAAAAAA=="
	raw := []byte(`{"protocol":"shadowsocks","listen":"10.0.0.2","port":31003,"settings":{"method":"2022-blake3-aes-128-gcm","password":"secret://core/` + testCore + `/` + testSecret + `","network":"tcp,udp"}}`)
	store := func(kind string, mode os.FileMode) {
		data, _ := json.Marshal(StoredSecret{Kind: kind, Password: password})
		if err := os.WriteFile(filename, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filename, mode); err != nil {
			t.Fatal(err)
		}
	}
	store("shadowsocks-password", 0600)
	resolved, err := Resolve(raw, dir, testCore)
	if err != nil || !Preflight(resolved).Valid || !strings.Contains(string(resolved), password) {
		t.Fatalf("SS resolution/build failed: %v", err)
	}
	if _, err := Resolve(raw, dir, testSecret); err == nil {
		t.Fatal("cross-core secret accepted")
	}
	store("reality-key", 0600)
	if _, err := Resolve(raw, dir, testCore); err == nil {
		t.Fatal("wrong secret kind accepted")
	}
	store("shadowsocks-password", 0644)
	if _, err := Resolve(raw, dir, testCore); err == nil {
		t.Fatal("public secret accepted")
	}
}

func TestRealitySecretsAreCoreScopedPersistentAndPublicOnly(t *testing.T) {
	dir := t.TempDir()
	first, err := GenerateSecret(dir, testCore, testSecret, "reality-key", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateSecret(dir, testCore, testSecret, "reality-key", "")
	if err != nil || first["publicKey"] != second["publicKey"] {
		t.Fatal("key retry is not idempotent")
	}
	data, _ := json.Marshal(first)
	if strings.Contains(string(data), "privateKey") {
		t.Fatal("private key leaked")
	}
	info, _ := os.Stat(filepath.Join(dir, testSecret+".json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("secret permissions")
	}
	profile := map[string]any{"protocol": "vless", "listen": "127.0.0.1", "port": 11245, "settings": map[string]any{"decryption": "none"}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"target": "example.com:443", "serverNames": []string{"example.com"}, "privateKey": first["reference"], "shortIds": []any{first["shortId"]}}}}
	raw, _ := json.Marshal(profile)
	resolved, err := Resolve(raw, dir, testCore)
	if err != nil || !Preflight(resolved).Valid {
		t.Fatalf("REALITY preflight failed: %v %+v", err, Preflight(resolved))
	}
	if _, err := Resolve(raw, dir, "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("cross-core reference accepted")
	}
}
func TestTLSSecretGenerationAndUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	secret, err := GenerateSecret(dir, testCore, testSecret, "tls-certificate", "lab.example.com")
	if err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{"protocol": "vless", "listen": "127.0.0.1", "port": 11245, "settings": map[string]any{"decryption": "none"}, "streamSettings": map[string]any{"network": "raw", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": secret["reference"], "keyFile": secret["reference"]}}}}}
	raw, _ := json.Marshal(profile)
	resolved, err := Resolve(raw, dir, testCore)
	if err != nil || !Preflight(resolved).Valid {
		t.Fatalf("TLS preflight failed: %v", err)
	}
	if _, err := Resolve([]byte(`{"streamSettings":{"tlsSettings":{"certificates":[{"keyFile":"/etc/shadow"}]}}}`), dir, testCore); err == nil {
		t.Fatal("arbitrary file access accepted")
	}
}
