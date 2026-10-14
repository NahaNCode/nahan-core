// Package routingpolicy binds managed-route consent to the local configuration.
package routingpolicy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	updater "github.com/NahaNCode/nahan-core/utility/update"
	"github.com/xtls/xray-core/infra/conf"
)

type Report struct {
	RuntimeVersion int      `json:"runtimeVersion"`
	Digest         string   `json:"digest"`
	Generation     int64    `json:"generation"`
	Enabled        bool     `json:"enabled"`
	HasRoute       bool     `json:"hasRoute"`
	HasDNS         bool     `json:"hasDNS"`
	HasInbound     bool     `json:"hasInbound"`
	DNSCompatible  bool     `json:"dnsCompatible"`
	Blockers       []string `json:"blockers"`
}

type Request struct {
	CoreID             string `json:"coreId"`
	ExpectedDigest     string `json:"expectedDigest"`
	ExpectedGeneration int64  `json:"expectedGeneration"`
	Enabled            bool   `json:"enabled"`
	Acknowledged       bool   `json:"acknowledged"`
}

type Config struct {
	CoreID, Key, Directory                        string
	RoutePath, DNSPath, InboundPath, OutboundPath string
	LegacyAllowed                                 bool
}

type journal struct {
	CoreID        string `json:"coreId"`
	Digest        string `json:"digest"`
	Generation    int64  `json:"generation"`
	Enabled       bool   `json:"enabled"`
	JobID         string `json:"jobId"`
	RequestDigest string `json:"requestDigest"`
	MAC           string `json:"mac"`
}

type Policy struct {
	mu            sync.Mutex
	c             Config
	state         journal
	invalid       bool
	startupDigest string
}

var ErrRejected = errors.New("routing_policy_rejected")

const maxGeneration int64 = 1<<63 - 1

func New(c Config) (*Policy, error) {
	if !updater.UUIDPattern.MatchString(c.CoreID) || len(c.Key) < 32 || c.Directory == "" {
		return nil, ErrRejected
	}
	p := &Policy{c: c}
	data, err := restrictedRead(p.path(), 16384)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		p.invalid = true
		return p, nil
	}
	if json.Unmarshal(data, &p.state) != nil || p.state.CoreID != c.CoreID || p.state.Generation < 1 || p.state.Generation >= maxGeneration-1 || len(p.state.Digest) != 64 || !hmac.Equal([]byte(p.state.MAC), []byte(p.sign(p.state))) {
		p.state = journal{}
		p.invalid = true
	}
	return p, nil
}

func (p *Policy) path() string { return filepath.Join(p.c.Directory, "managed-egress-policy.json") }
func (p *Policy) sign(j journal) string {
	j.MAC = ""
	b, _ := json.Marshal(j)
	m := hmac.New(sha256.New, []byte(p.c.Key))
	m.Write([]byte("nahan-routing-policy-v1\x00"))
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}
func restrictedRead(path string, limit int64) ([]byte, error) {
	i, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		return nil, ErrRejected
	}
	return boundedRead(path, limit)
}
func boundedRead(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() {
		return nil, ErrRejected
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrRejected
	}
	return b, nil
}
func (p *Policy) save(j journal) error {
	if i, err := os.Lstat(p.path()); err == nil {
		if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
			return ErrRejected
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrRejected
	}
	j.MAC = p.sign(j)
	if err := updater.Atomic(p.path(), j); err != nil {
		return ErrRejected
	}
	p.state = j
	return nil
}

func (p *Policy) Inspect() Report { p.mu.Lock(); defer p.mu.Unlock(); return p.inspect() }
func (p *Policy) inspect() Report {
	r := Report{RuntimeVersion: 1, HasRoute: p.c.RoutePath != "", HasDNS: p.c.DNSPath != "", HasInbound: p.c.InboundPath != "", DNSCompatible: true, Blockers: []string{}}
	h := hmac.New(sha256.New, []byte(p.c.Key))
	h.Write([]byte("nahan-routing-inputs-v1\x00" + p.c.CoreID))
	paths := []string{p.c.RoutePath, p.c.DNSPath, p.c.InboundPath, p.c.OutboundPath}
	for n, path := range paths {
		// Hash structured path/content inputs; never disclose local paths or DNS addresses.
		b := []byte{}
		var err error
		if path != "" {
			b, err = boundedRead(path, 1<<20)
		}
		part, _ := json.Marshal(struct {
			Index      int
			Path       string
			Content    []byte
			Unreadable bool
		}{n, path, b, err != nil})
		h.Write(part)
		if err != nil {
			r.Blockers = append(r.Blockers, "configuration_unreadable")
			if n == 1 {
				r.DNSCompatible = false
			}
		}
		if n == 1 && path != "" && err == nil && !supportedDNS(b) {
			r.DNSCompatible = false
			r.Blockers = append(r.Blockers, "dns_unsupported")
		}
	}
	r.Digest = hex.EncodeToString(h.Sum(nil))
	if p.startupDigest == "" {
		p.startupDigest = r.Digest
	} else if p.startupDigest != r.Digest {
		r.Blockers = append(r.Blockers, "configuration_restart_required")
	}
	if p.state.Generation > 0 {
		b, err := restrictedRead(p.path(), 16384)
		var disk journal
		if err != nil || json.Unmarshal(b, &disk) != nil || disk.MAC != p.state.MAC || !hmac.Equal([]byte(disk.MAC), []byte(p.sign(disk))) {
			p.invalid = true
		}
	}
	if r.HasInbound {
		r.Blockers = append(r.Blockers, "custom_inbound_unsupported")
	}
	if p.invalid {
		r.Blockers = append(r.Blockers, "policy_journal_invalid")
	}
	if !p.invalid && (p.state.Generation == 0 || p.state.Digest != r.Digest) {
		j := journal{CoreID: p.c.CoreID, Digest: r.Digest, Generation: p.state.Generation + 1}
		if p.state.Generation == 0 {
			j.Enabled = !r.HasDNS && !r.HasInbound && (!r.HasRoute || p.c.LegacyAllowed)
		}
		if p.save(j) != nil {
			r.Blockers = append(r.Blockers, "policy_persistence_failed")
		}
	}
	r.Generation = p.state.Generation
	r.Enabled = len(r.Blockers) == 0 && p.state.Digest == r.Digest && p.state.Enabled
	return r
}

func supportedDNS(b []byte) bool {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || raw == nil {
		return false
	}
	allowed := map[string]bool{"servers": true, "queryStrategy": true, "disableCache": true, "disableFallback": true, "disableFallbackIfMatch": true, "tag": true, "clientIp": true}
	for k := range raw {
		if !allowed[k] {
			return false
		}
	}
	var servers []json.RawMessage
	if v, ok := raw["servers"]; ok && json.Unmarshal(v, &servers) != nil {
		return false
	}
	for _, v := range servers {
		var address string
		if json.Unmarshal(v, &address) != nil {
			var server map[string]json.RawMessage
			if json.Unmarshal(v, &server) != nil || json.Unmarshal(server["address"], &address) != nil {
				return false
			}
		}
		if strings.Contains(strings.ToLower(address), "fakedns") {
			return false
		}
	}
	var cfg conf.DNSConfig
	if json.Unmarshal(b, &cfg) != nil {
		return false
	}
	_, err := cfg.Build()
	return err == nil
}

func (p *Policy) Apply(payload json.RawMessage, jobID string) (Report, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.inspect()
	var req Request
	var fields map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if len(payload) > 4096 || json.Unmarshal(payload, &fields) != nil || string(fields["enabled"]) == "null" || fields["enabled"] == nil || d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || req.CoreID != p.c.CoreID || !req.Acknowledged || !updater.UUIDPattern.MatchString(jobID) {
		return r, ErrRejected
	}
	b, _ := json.Marshal(req)
	sum := sha256.Sum256(b)
	rd := hex.EncodeToString(sum[:])
	if p.state.JobID == jobID {
		if p.state.RequestDigest == rd && p.state.Digest == r.Digest && len(r.Blockers) == 0 {
			return r, nil
		}
		return r, ErrRejected
	}
	if len(r.Blockers) > 0 || r.Generation >= maxGeneration-2 || req.ExpectedDigest != r.Digest || req.ExpectedGeneration != r.Generation {
		return r, ErrRejected
	}
	j := p.state
	j.Enabled = req.Enabled
	j.Generation++
	j.JobID = jobID
	j.RequestDigest = rd
	if p.save(j) != nil {
		return r, ErrRejected
	}
	return p.inspect(), nil
}
