package egress

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
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/NahaNCode/nahan-core/utility/entryprofile"
)

var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type CredentialScope struct {
	RouteID      string `json:"routeId"`
	SourceCoreID string `json:"sourceCoreId"`
	TargetCoreID string `json:"targetCoreId"`
	Revision     int64  `json:"revision"`
	ExpiresAt    int64  `json:"expiresAt"`
}

func (s CredentialScope) Label() (string, error) {
	if !uuid.MatchString(s.RouteID) || !uuid.MatchString(s.SourceCoreID) || !uuid.MatchString(s.TargetCoreID) || s.SourceCoreID == s.TargetCoreID || s.Revision < 1 {
		return "", errors.New("invalid egress credential scope")
	}
	remaining := s.ExpiresAt - time.Now().Unix()
	if remaining <= 0 || remaining > 600 {
		return "", errors.New("expired egress credential scope")
	}
	return fmt.Sprintf("nahan-egress-v1:%s:%s:%s:%d:%d", s.RouteID, s.SourceCoreID, s.TargetCoreID, s.Revision, s.ExpiresAt), nil
}

// RecipientIdentity is local to the source core, never to a browser or panel.
// O_EXCL also prevents an existing key or symlink from being overwritten.
func RecipientIdentity(filename string) (*rsa.PrivateKey, string, error) {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			return nil, "", err
		}
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, "", err
		}
		data := x509.MarshalPKCS1PrivateKey(key)
		file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, "", err
		}
		_, writeErr := file.Write(data)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return nil, "", writeErr
		}
		if closeErr != nil {
			return nil, "", closeErr
		}
		info, err = os.Lstat(filename)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, "", errors.New("unsafe egress recipient key")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, "", err
	}
	key, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 {
		return nil, "", errors.New("invalid egress recipient key")
	}
	if err = key.Validate(); err != nil {
		return nil, "", errors.New("invalid egress recipient key")
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return key, base64.StdEncoding.EncodeToString(public), nil
}

type SSCredential struct {
	Method   string `json:"method"`
	Password string `json:"password"`
}

func validCredential(c SSCredential) bool {
	if c.Password == "" || len(c.Password) > 1024 {
		return false
	}
	switch c.Method {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
		return true
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		data, err := base64.StdEncoding.DecodeString(c.Password)
		size := 32
		if c.Method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		return err == nil && len(data) == size
	}
	return false
}

func ExportCredential(profile []byte, directory, coreID, recipient string, scope CredentialScope) (entryprofile.SealedResult, error) {
	label, err := scope.Label()
	if err != nil || coreID != scope.TargetCoreID {
		return entryprofile.SealedResult{}, errors.New("egress export scope rejected")
	}
	// Only a destination's managed local secret may be exported. Inline keys and
	// unrelated protocol fields must not be used to turn this into a key oracle.
	var inbound struct {
		Protocol string       `json:"protocol"`
		Settings SSCredential `json:"settings"`
	}
	if len(profile) > 65536 || json.Unmarshal(profile, &inbound) != nil || inbound.Protocol != "shadowsocks" || len(inbound.Settings.Password) < 14 || inbound.Settings.Password[:14] != "secret://core/" {
		return entryprofile.SealedResult{}, errors.New("unmanaged egress secret")
	}
	password, err := entryprofile.ResolveSSCredential(inbound.Settings.Password, inbound.Settings.Method, directory, coreID)
	if err != nil {
		return entryprofile.SealedResult{}, errors.New("egress secret resolution failed")
	}
	inbound.Settings.Password = password
	if !validCredential(inbound.Settings) {
		return entryprofile.SealedResult{}, errors.New("unsupported egress credential")
	}
	data, _ := json.Marshal(inbound.Settings)
	return entryprofile.Seal(data, recipient, label)
}

func OpenCredential(sealed entryprofile.SealedResult, key *rsa.PrivateKey, sourceCoreID string, scope CredentialScope) (SSCredential, error) {
	var result SSCredential
	plain, err := openEnvelope(sealed, key, sourceCoreID, scope, "")
	if err != nil {
		return result, err
	}
	if json.Unmarshal(plain, &result) != nil || !validCredential(result) {
		return SSCredential{}, errors.New("invalid egress credential")
	}
	return result, nil
}

func openEnvelope(sealed entryprofile.SealedResult, key *rsa.PrivateKey, sourceCoreID string, scope CredentialScope, domain string) ([]byte, error) {
	label, err := scope.Label()
	if err != nil || sourceCoreID != scope.SourceCoreID || key == nil {
		return nil, errors.New("egress import scope rejected")
	}
	if len(sealed.Ciphertext) > 4096 || len(sealed.WrappedKey) > 1024 || len(sealed.Nonce) > 32 {
		return nil, errors.New("oversized egress envelope")
	}
	wrapped, err := base64.StdEncoding.DecodeString(sealed.WrappedKey)
	if err != nil {
		return nil, errors.New("invalid egress envelope")
	}
	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, nil)
	if err != nil || len(secret) != 32 {
		return nil, errors.New("egress recipient mismatch")
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, errors.New("invalid egress envelope")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid egress nonce")
	}
	data, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid egress ciphertext")
	}
	plain, err := gcm.Open(nil, nonce, data, []byte(label+domain))
	if err != nil {
		return nil, errors.New("egress credential authentication failed")
	}
	return plain, nil
}
