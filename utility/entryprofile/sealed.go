package entryprofile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type SealedResult struct {
	Ciphertext string `json:"ciphertext"`
	WrappedKey string `json:"wrappedKey"`
	Nonce      string `json:"nonce"`
}

func Seal(data []byte, publicKey, scope string) (SealedResult, error) {
	var result SealedResult
	encoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return result, errors.New("invalid recipient")
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		return result, errors.New("invalid recipient")
	}
	recipient, ok := parsed.(*rsa.PublicKey)
	if !ok || recipient.N.BitLen() < 2048 || recipient.N.BitLen() > 4096 {
		return result, errors.New("invalid recipient")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return result, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return result, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return result, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return result, err
	}
	encrypted := gcm.Seal(nil, nonce, data, []byte(scope))
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipient, key, nil)
	if err != nil {
		return result, err
	}
	return SealedResult{base64.StdEncoding.EncodeToString(encrypted), base64.StdEncoding.EncodeToString(wrapped), base64.StdEncoding.EncodeToString(nonce)}, nil
}

// The panel relays ciphertext only; the requesting browser owns the decryption key.
func SealSSConfig(input []byte, directory, coreID, jobID string) (SealedResult, error) {
	var payload struct {
		Profile   json.RawMessage `json:"profile"`
		Address   string          `json:"address"`
		PublicKey string          `json:"publicKey"`
	}
	if !identity.MatchString(coreID) || !identity.MatchString(jobID) || json.Unmarshal(input, &payload) != nil {
		return SealedResult{}, errors.New("invalid request")
	}
	resolved, err := Resolve(payload.Profile, directory, coreID)
	if err != nil || !Preflight(resolved).Valid {
		return SealedResult{}, errors.New("invalid profile")
	}
	var inbound struct {
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Settings struct {
			Method   string `json:"method"`
			Password string `json:"password"`
		} `json:"settings"`
	}
	if json.Unmarshal(resolved, &inbound) != nil || inbound.Protocol != "shadowsocks" || inbound.Settings.Password == "" || inbound.Port < 1 || inbound.Port > 65535 {
		return SealedResult{}, errors.New("unsupported profile")
	}
	if len(payload.Address) > 253 || payload.Address == "" {
		return SealedResult{}, errors.New("invalid endpoint")
	}
	credential := base64.RawURLEncoding.EncodeToString([]byte(inbound.Settings.Method + ":" + inbound.Settings.Password))
	if strings.HasPrefix(inbound.Settings.Method, "2022-") {
		credential = url.UserPassword(inbound.Settings.Method, inbound.Settings.Password).String()
	}
	uri := fmt.Sprintf("ss://%s@%s#%s", credential, net.JoinHostPort(payload.Address, strconv.Itoa(inbound.Port)), url.PathEscape("NahaN SS test"))
	return Seal([]byte(uri), payload.PublicKey, "nahan-ss-test:"+coreID+":"+jobID)
}
