package entryprofile

import (
	"crypto/ecdh"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Every delivery is bound to both jobs, both cores and one exact draft revision.
type SecretTransferScope struct {
	SourceCoreID string `json:"sourceCoreId"`
	TargetCoreID string `json:"targetCoreId"`
	ExportID     string `json:"exportId"`
	ImportID     string `json:"importId"`
	DraftID      string `json:"draftId"`
	Revision     int64  `json:"revision"`
	Reference    string `json:"reference"`
	Kind         string `json:"kind"`
	ExpiresAt    int64  `json:"expiresAt"`
}

func (s SecretTransferScope) label() (string, error) {
	prefix := "secret://core/" + s.SourceCoreID + "/"
	for _, id := range []string{s.SourceCoreID, s.TargetCoreID, s.ExportID, s.ImportID, s.DraftID} {
		if !identity.MatchString(id) {
			return "", errors.New("invalid secret transfer identity")
		}
	}
	remaining := s.ExpiresAt - time.Now().Unix()
	if s.Revision < 1 || remaining <= 0 || remaining > 600 || !strings.HasPrefix(s.Reference, prefix) || !identity.MatchString(strings.TrimPrefix(s.Reference, prefix)) {
		return "", errors.New("invalid secret transfer scope")
	}
	if s.Kind != "reality-key" && s.Kind != "tls-certificate" && s.Kind != "shadowsocks-password" {
		return "", errors.New("unsupported secret transfer kind")
	}
	return fmt.Sprintf("nahan-entry-secret-v1:%s:%s:%s:%s:%s:%d:%s:%s:%d", s.SourceCoreID, s.TargetCoreID, s.ExportID, s.ImportID, s.DraftID, s.Revision, s.Reference, s.Kind, s.ExpiresAt), nil
}

func validTransferredSecret(s StoredSecret) bool {
	switch s.Kind {
	case "reality-key":
		data, err := base64.RawURLEncoding.DecodeString(s.PrivateKey)
		if err != nil || len(data) != 32 {
			return false
		}
		key, err := ecdh.X25519().NewPrivateKey(data)
		return err == nil && s.PublicKey == base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) && regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(s.ShortID) && s.Certificate == "" && s.Password == "" && s.Method == ""
	case "tls-certificate":
		_, err := tls.X509KeyPair([]byte(s.Certificate), []byte(s.PrivateKey))
		return err == nil && s.Password == "" && s.Method == "" && s.PublicKey == "" && s.ShortID == ""
	case "shadowsocks-password":
		size := 32
		switch s.Method {
		case "2022-blake3-aes-128-gcm":
			size = 16
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
		default:
			return false
		}
		data, err := base64.StdEncoding.DecodeString(s.Password)
		return err == nil && len(data) == size && s.PrivateKey == "" && s.PublicKey == "" && s.ShortID == "" && s.Certificate == ""
	}
	return false
}

func ExportSecret(directory, coreID, jobID, recipient string, scope SecretTransferScope) (SealedResult, error) {
	label, err := scope.label()
	if err != nil || coreID != scope.SourceCoreID || jobID != scope.ExportID {
		return SealedResult{}, errors.New("secret export scope rejected")
	}
	id := strings.TrimPrefix(scope.Reference, "secret://core/"+coreID+"/")
	secret, err := readSecret(filepath.Join(directory, id+".json"))
	if err != nil || secret.Kind != scope.Kind || !validTransferredSecret(secret) {
		return SealedResult{}, errors.New("secret export rejected")
	}
	data, err := json.Marshal(secret)
	if err != nil || len(data) > 8000 {
		return SealedResult{}, errors.New("secret export rejected")
	}
	return Seal(data, recipient, label)
}

func ImportSecret(directory, coreID, jobID string, recipient *rsa.PrivateKey, scope SecretTransferScope, envelope SealedResult) (map[string]any, error) {
	label, err := scope.label()
	if err != nil || coreID != scope.TargetCoreID || jobID != scope.ImportID {
		return nil, errors.New("secret import scope rejected")
	}
	data, err := Open(envelope, recipient, label)
	if err != nil {
		return nil, err
	}
	var secret StoredSecret
	if json.Unmarshal(data, &secret) != nil || secret.Kind != scope.Kind || !validTransferredSecret(secret) {
		return nil, errors.New("invalid transferred secret")
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	filename := filepath.Join(directory, jobID+".json")
	previous, err := readSecret(filename)
	if err == nil {
		if previous != secret {
			return nil, errors.New("secret import identity conflict")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		// Publish only a fully written, synced private file, without replacing an existing identity.
		file, err := os.CreateTemp(directory, ".secret-transfer-*")
		if err != nil {
			return nil, err
		}
		tmp := file.Name()
		defer os.Remove(tmp)
		_, writeErr := file.Write(data)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if err = os.Link(tmp, filename); err != nil {
			return nil, errors.New("secret import commit rejected")
		}
	} else {
		return nil, err
	}
	result := map[string]any{"reference": "secret://core/" + coreID + "/" + jobID}
	if secret.Kind == "reality-key" {
		result["publicKey"], result["shortId"] = secret.PublicKey, secret.ShortID
	}
	if secret.Kind == "tls-certificate" {
		result["certificate"] = secret.Certificate
	}
	return result, nil
}
