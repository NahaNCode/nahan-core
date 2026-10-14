package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"
)

const PublicKey = "xiql0i80KrTc6ehKNhMQJuhnANSK7Q368RcCAoFO5Bc="
const CatalogURL = "https://github.com/NahaNCode/nahan-core/releases/latest/download/updates.json"

type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Image  string `json:"image,omitempty"`
}
type Release struct {
	Version     string           `json:"version"`
	Commit      string           `json:"commit"`
	PublishedAt int64            `json:"publishedAt"`
	ExpiresAt   int64            `json:"expiresAt"`
	Assets      map[string]Asset `json:"assets"`
}
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

var VersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
var DigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func Verify(data []byte, public string, now time.Time) (Release, error) {
	var envelope Envelope
	var release Release
	if len(data) > 65536 || json.Unmarshal(data, &envelope) != nil {
		return release, errors.New("invalid signed catalog")
	}
	payload, e := base64.StdEncoding.DecodeString(envelope.Payload)
	if e != nil {
		return release, errors.New("invalid catalog payload")
	}
	signature, e := base64.StdEncoding.DecodeString(envelope.Signature)
	if e != nil {
		return release, errors.New("invalid catalog signature")
	}
	key, e := base64.StdEncoding.DecodeString(public)
	if e != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, payload, signature) {
		return release, errors.New("catalog signature rejected")
	}
	if json.Unmarshal(payload, &release) != nil || !VersionPattern.MatchString(release.Version) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(release.Commit) || release.PublishedAt > now.Unix()+300 || release.ExpiresAt <= now.Unix() || release.ExpiresAt-release.PublishedAt > 180*86400 || len(release.Assets) == 0 || len(release.Assets) > 16 {
		return release, errors.New("invalid release metadata")
	}
	for arch, a := range release.Assets {
		if !regexp.MustCompile(`^linux-(amd64|arm64|386|armv[567]|riscv64)$`).MatchString(arch) || !DigestPattern.MatchString(a.SHA256) || a.Size < 1 || a.Size > 256<<20 || !allowedURL(a.URL) {
			return Release{}, errors.New("invalid release asset")
		}
	}
	return release, nil
}
func allowedURL(value string) bool {
	u, e := url.Parse(value)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return false
	}
	return u.Host == "github.com" && regexp.MustCompile(`^/NahaNCode/nahan-core/releases/download/v[0-9]+\.[0-9]+\.[0-9]+/NahaN-linux-[a-z0-9]+$`).MatchString(u.Path)
}
func HTTPClient() *http.Client {
	return &http.Client{Timeout: 120 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || r.URL.Scheme != "https" || r.URL.User != nil || !(r.URL.Hostname() == "github.com" || r.URL.Hostname() == "release-assets.githubusercontent.com" || r.URL.Hostname() == "objects.githubusercontent.com") {
			return errors.New("release redirect rejected")
		}
		return nil
	}}
}
func Catalog(ctx context.Context) (Release, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", CatalogURL, nil)
	if e != nil {
		return Release{}, e
	}
	response, e := HTTPClient().Do(req)
	if e != nil {
		return Release{}, errors.New("release catalog unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return Release{}, errors.New("release catalog unavailable")
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil {
		return Release{}, e
	}
	return Verify(data, PublicKey, time.Now())
}
func Hash(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func Download(ctx context.Context, a Asset, path string) error {
	if !allowedURL(a.URL) || !DigestPattern.MatchString(a.SHA256) || a.Size < 1 || a.Size > 256<<20 {
		return errors.New("invalid download")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", a.URL, nil)
	if e != nil {
		return e
	}
	response, e := HTTPClient().Do(req)
	if e != nil {
		return errors.New("release download unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("release download unavailable")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(response.Body, a.Size+1))
	if e != nil || n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		os.Remove(path)
		return errors.New("release checksum rejected")
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return f.Chmod(0755)
}
