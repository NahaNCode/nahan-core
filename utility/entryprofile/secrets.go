package entryprofile

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var identity = regexp.MustCompile(`^[a-f0-9-]{36}$`)

type StoredSecret struct {
	Kind        string `json:"kind"`
	PrivateKey  string `json:"privateKey,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Password    string `json:"password,omitempty"`
	Method      string `json:"method,omitempty"`
}

func GenerateSecret(directory, coreID, id, kind, serverName string) (map[string]any, error) {
	if !identity.MatchString(coreID) || !identity.MatchString(id) {
		return nil, errors.New("invalid identity")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	filename := filepath.Join(directory, id+".json")
	secret, err := readSecret(filename)
	if errors.Is(err, os.ErrNotExist) {
		secret = StoredSecret{Kind: kind}
		switch kind {
		case "shadowsocks-password":
			size := 32
			switch serverName {
			case "2022-blake3-aes-128-gcm":
				size = 16
			case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
			default:
				return nil, errors.New("unsupported SS cipher")
			}
			key := make([]byte, size)
			if _, err := rand.Read(key); err != nil {
				return nil, err
			}
			secret.Password = base64.StdEncoding.EncodeToString(key)
			secret.Method = serverName
		case "reality-key":
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			secret.PrivateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
			secret.PublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			short := make([]byte, 8)
			if _, err := rand.Read(short); err != nil {
				return nil, err
			}
			secret.ShortID = hex.EncodeToString(short)
		case "tls-certificate":
			if !regexp.MustCompile(`^[a-zA-Z0-9.-]{1,253}$`).MatchString(serverName) {
				return nil, errors.New("invalid certificate name")
			}
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}
			serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			if err != nil {
				return nil, err
			}
			template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				return nil, err
			}
			secret.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			secret.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
		default:
			return nil, errors.New("unsupported secret kind")
		}
		data, _ := json.Marshal(secret)
		file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		if _, err = file.Write(data); err != nil {
			file.Close()
			return nil, err
		}
		if err = file.Sync(); err != nil {
			file.Close()
			return nil, err
		}
		if err = file.Close(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if secret.Kind != kind {
		return nil, errors.New("secret kind mismatch")
	}
	if kind == "shadowsocks-password" && secret.Method != "" && secret.Method != serverName {
		return nil, errors.New("SS cipher mismatch")
	}
	result := map[string]any{"reference": "secret://core/" + coreID + "/" + id}
	if kind == "reality-key" {
		result["publicKey"] = secret.PublicKey
		result["shortId"] = secret.ShortID
	} else if kind == "tls-certificate" {
		result["certificate"] = secret.Certificate
	}
	return result, nil
}
func readSecret(filename string) (StoredSecret, error) {
	var result StoredSecret
	info, err := os.Lstat(filename)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return result, errors.New("unsafe secret permissions")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}

// This narrower resolver cannot traverse a profile or materialize TLS files.
func ResolveSSCredential(reference, method, directory, coreID string) (string, error) {
	prefix := "secret://core/" + coreID + "/"
	if !identity.MatchString(coreID) || !strings.HasPrefix(reference, prefix) || !identity.MatchString(strings.TrimPrefix(reference, prefix)) {
		return "", errors.New("secret scope mismatch")
	}
	secret, err := readSecret(filepath.Join(directory, strings.TrimPrefix(reference, prefix)+".json"))
	if err != nil || secret.Kind != "shadowsocks-password" || secret.Password == "" || secret.Method != method {
		return "", errors.New("SS secret scope or cipher mismatch")
	}
	return secret.Password, nil
}

func Resolve(input []byte, directory, coreID string) ([]byte, error) {
	if len(input) > MaxBytes {
		return nil, errors.New("oversized profile")
	}
	if err := uniqueKeys(json.NewDecoder(strings.NewReader(string(input))), 0); err != nil {
		return nil, errors.New("ambiguous profile JSON")
	}
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(input)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	var visit func(any, int) error
	visit = func(value any, depth int) error {
		if depth > 24 {
			return errors.New("nesting")
		}
		switch object := value.(type) {
		case map[string]any:
			for key, item := range object {
				if text, ok := item.(string); ok && strings.HasPrefix(text, "secret://") {
					prefix := "secret://core/" + coreID + "/"
					if !strings.HasPrefix(text, prefix) || !identity.MatchString(strings.TrimPrefix(text, prefix)) {
						return errors.New("secret scope mismatch")
					}
					id := strings.TrimPrefix(text, prefix)
					secret, err := readSecret(filepath.Join(directory, id+".json"))
					if err != nil {
						return err
					}
					switch key {
					case "password":
						if secret.Kind != "shadowsocks-password" || secret.Password == "" {
							return errors.New("secret kind mismatch")
						}
						object[key] = secret.Password
					case "privateKey":
						if secret.Kind != "reality-key" {
							return errors.New("secret kind mismatch")
						}
						object[key] = secret.PrivateKey
					case "certificateFile", "keyFile":
						if secret.Kind != "tls-certificate" {
							return errors.New("secret kind mismatch")
						}
						extension := ".cert.pem"
						content := secret.Certificate
						if key == "keyFile" {
							extension = ".key.pem"
							content = secret.PrivateKey
						}
						filename := filepath.Join(directory, id+extension)
						if info, err := os.Lstat(filename); err == nil {
							if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
								return errors.New("unsafe TLS file")
							}
						} else if !errors.Is(err, os.ErrNotExist) {
							return err
						}
						if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
							return err
						}
						object[key] = filename
					default:
						return errors.New("unsupported secret field")
					}
				} else if key == "certificateFile" || key == "keyFile" || key == "masterKeyLog" {
					if text, ok := item.(string); ok && text != "" {
						return errors.New("unmanaged file path")
					}
				}
				// Resolved values are local, not traversed a second time as user paths.
				if _, ok := item.(string); !ok {
					if err := visit(object[key], depth+1); err != nil {
						return err
					}
				}
			}
		case []any:
			for _, item := range object {
				if err := visit(item, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(document, 0); err != nil {
		return nil, err
	}
	return json.Marshal(document)
}
