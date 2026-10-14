package egress

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"github.com/xtls/xray-core/infra/conf"
)

type ExternalScope struct {
	ID        string `json:"id"`
	CoreID    string `json:"coreId"`
	ExpiresAt int64  `json:"expiresAt"`
}

func (s ExternalScope) Label() (string, error) {
	if !uuid.MatchString(s.ID) || !uuid.MatchString(s.CoreID) || s.ExpiresAt <= time.Now().Unix() || s.ExpiresAt > time.Now().Add(600*time.Second).Unix() {
		return "", errors.New("invalid external import scope")
	}
	return fmt.Sprintf("nahan-egress-external-v1:%s:%s:%d", s.CoreID, s.ID, s.ExpiresAt), nil
}

type ExternalBinding struct {
	ID       string `json:"id"`
	Digest   string `json:"digest"`
	Protocol string `json:"protocol"`
}
type ExternalImport struct {
	Scope    ExternalScope             `json:"scope"`
	Digest   string                    `json:"digest"`
	Protocol string                    `json:"protocol"`
	Envelope entryprofile.SealedResult `json:"envelope"`
}

func ValidateExternal(data []byte) (string, error) {
	if len(data) == 0 || len(data) > 16384 || !json.Valid(data) {
		return "", errors.New("invalid external outbound")
	}
	var tree any
	if json.Unmarshal(data, &tree) != nil || unsafeExternal(tree) {
		return "", errors.New("unsafe external outbound")
	}
	var config conf.OutboundDetourConfig
	if json.Unmarshal(data, &config) != nil || config.Tag != "" || config.ProxySettings != nil {
		return "", errors.New("external handler identity must be managed")
	}
	switch config.Protocol {
	case "vless", "vmess", "trojan", "shadowsocks":
	default:
		return "", errors.New("unsupported external outbound protocol")
	}
	if _, err := config.Build(); err != nil {
		return "", errors.New("external outbound build failed")
	}
	return config.Protocol, nil
}
func unsafeExternal(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			switch key {
			case "allowInsecure", "allowInsecureCiphers":
				if item != false {
					return true
				}
			case "dialerProxy", "certificateFile", "keyFile", "caFile", "downloadSettings", "proxySettings", "extra":
				return true
			}
			if unsafeExternal(item) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if unsafeExternal(item) {
				return true
			}
		}
	}
	return false
}

// User-owned credentials cross the panel as ciphertext, then remain encrypted
// locally. They are not short-lived managed destination principal leases.
func ImportExternal(directory, coreID, credential string, key *rsa.PrivateKey, request ExternalImport) error {
	label, err := request.Scope.Label()
	if err != nil || request.Scope.CoreID != coreID || key == nil {
		return errors.New("external recipient mismatch")
	}
	sealed := request.Envelope
	if len(sealed.Ciphertext) > 22000 || len(sealed.WrappedKey) > 1024 || len(sealed.Nonce) > 32 {
		return errors.New("oversized external envelope")
	}
	wrapped, err := base64.StdEncoding.DecodeString(sealed.WrappedKey)
	if err != nil {
		return err
	}
	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, nil)
	if err != nil || len(secret) != 32 {
		return errors.New("external recipient mismatch")
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return errors.New("invalid external nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(label))
	if err != nil {
		return errors.New("external envelope authentication failed")
	}
	hash := sha256.Sum256(plain)
	if hex.EncodeToString(hash[:]) != request.Digest {
		return errors.New("external import digest mismatch")
	}
	protocol, err := ValidateExternal(plain)
	if err != nil || protocol != request.Protocol {
		return errors.New("external protocol mismatch")
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe external directory")
	}
	filename := filepath.Join(directory, request.Scope.ID+".bin")
	old, err := LoadState(filename, coreID, credential)
	if err == nil {
		if string(old.Plan) != string(plain) {
			return errors.New("external identity is immutable")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	files, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(files) >= 256 {
		return errors.New("external inventory capacity reached")
	}
	return SaveState(filename, coreID, credential, State{CoreID: coreID, ExpiresAt: time.Unix(request.Scope.ExpiresAt, 0), Plan: plain})
}

func ReadExternal(directory, coreID, credential string, binding ExternalBinding) (json.RawMessage, error) {
	if !uuid.MatchString(binding.ID) || len(binding.Digest) != 64 {
		return nil, errors.New("invalid external binding")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe external directory")
	}
	state, err := LoadState(filepath.Join(directory, binding.ID+".bin"), coreID, credential)
	if err != nil {
		return nil, errors.New("external outbound unavailable")
	}
	hash := sha256.Sum256(state.Plan)
	if hex.EncodeToString(hash[:]) != binding.Digest {
		return nil, errors.New("external binding changed")
	}
	protocol, err := ValidateExternal(state.Plan)
	if err != nil || protocol != binding.Protocol {
		return nil, errors.New("invalid stored external outbound")
	}
	return state.Plan, nil
}
