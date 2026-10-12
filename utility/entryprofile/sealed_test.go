package entryprofile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealedSSConfigBrowserDecryptsSIP002WithoutServerPlaintext(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	recipient := base64.StdEncoding.EncodeToString(spki)
	directory := t.TempDir()
	password := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{255}, 16))
	secret, _ := json.Marshal(StoredSecret{Kind: "shadowsocks-password", Password: password})
	if err = os.WriteFile(filepath.Join(directory, testSecret+".json"), secret, 0600); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"address": "10.0.0.2", "publicKey": recipient, "profile": map[string]any{"protocol": "shadowsocks", "listen": "10.0.0.2", "port": 31003, "settings": map[string]any{"method": "2022-blake3-aes-128-gcm", "password": "secret://core/" + testCore + "/" + testSecret, "network": "tcp,udp"}}})
	jobID := "33333333-3333-4333-8333-333333333333"
	sealed, err := SealSSConfig(input, directory, testCore, jobID)
	if err != nil {
		t.Fatal(err)
	}
	serialized, _ := json.Marshal(sealed)
	if strings.Contains(string(serialized), password) || strings.Contains(string(serialized), "ss://") {
		t.Fatal("plaintext leaked")
	}
	wrapped, _ := base64.StdEncoding.DecodeString(sealed.WrappedKey)
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, nil)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonce, _ := base64.StdEncoding.DecodeString(sealed.Nonce)
	encrypted, _ := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if _, err = gcm.Open(nil, nonce, encrypted, []byte("wrong scope")); err == nil {
		t.Fatal("scope tampering accepted")
	}
	decoded, err := gcm.Open(nil, nonce, encrypted, []byte("nahan-ss-test:"+testCore+":"+jobID))
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(string(decoded))
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := uri.User.Password()
	if uri.Scheme != "ss" || uri.User.Username() != "2022-blake3-aes-128-gcm" || actual != password || uri.Host != "10.0.0.2:31003" {
		t.Fatal("invalid SIP002 URI")
	}
	if _, err = SealSSConfig(input, directory, testSecret, jobID); err == nil {
		t.Fatal("cross-core export allowed")
	}
	if _, err = Seal([]byte("secret"), "not-a-key", "scope"); err == nil {
		t.Fatal("bad recipient accepted")
	}
}
