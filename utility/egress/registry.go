package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Binding struct {
	EntryID  int64  `json:"entryId,omitempty"`
	Inbound  string `json:"inbound"`
	Outbound string `json:"outbound"`
}

type Snapshot struct {
	Revision     int64     `json:"revision"`
	LeaseSeconds int       `json:"leaseSeconds"`
	Bindings     []Binding `json:"bindings"`
}

// Registry publishes a complete routing snapshot; readers never observe a
// partially staged route. An expired managed binding remains fail-closed.
type Registry struct {
	mu       sync.RWMutex
	revision int64
	digest   string
	expires  time.Time
	bindings map[string]string
	entries  map[int64]string
	users    map[string]int
}

func Canonical(s Snapshot) (Snapshot, string, error) {
	if s.Revision < 1 || s.LeaseSeconds < 10 || s.LeaseSeconds > 300 || len(s.Bindings) > 1024 {
		return s, "", errors.New("invalid egress snapshot")
	}
	s.Bindings = append([]Binding(nil), s.Bindings...)
	sort.Slice(s.Bindings, func(i, j int) bool { return s.Bindings[i].Inbound < s.Bindings[j].Inbound })
	entries := map[int64]bool{}
	for i, b := range s.Bindings {
		if b.EntryID < 0 || (b.EntryID > 0 && entries[b.EntryID]) {
			return s, "", errors.New("ambiguous egress entry identity")
		}
		if b.EntryID > 0 {
			entries[b.EntryID] = true
		}
		if b.Inbound == "" || b.Outbound == "" || len(b.Inbound) > 128 || len(b.Outbound) > 128 || strings.ContainsAny(b.Inbound+b.Outbound, "\r\n\x00") || (i > 0 && s.Bindings[i-1].Inbound == b.Inbound) {
			return s, "", errors.New("ambiguous egress binding")
		}
	}
	data, _ := json.Marshal(s)
	digest := sha256.Sum256(data)
	return s, hex.EncodeToString(digest[:]), nil
}

func (r *Registry) Replace(s Snapshot, available func(string) bool) error {
	s, digest, err := Canonical(s)
	if err != nil {
		return err
	}
	if available == nil {
		return errors.New("missing outbound validator")
	}
	next := make(map[string]string, len(s.Bindings))
	entries := make(map[int64]string)
	for _, b := range s.Bindings {
		if !available(b.Outbound) {
			return errors.New("egress outbound unavailable")
		}
		next[b.Inbound] = b.Outbound
		if b.EntryID > 0 {
			entries[b.EntryID] = b.Outbound
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.Revision < r.revision || (s.Revision == r.revision && r.digest != digest) {
		return errors.New("egress revision conflict")
	}
	r.revision, r.digest, r.bindings = s.Revision, digest, next
	r.entries = entries
	r.expires = time.Now().Add(time.Duration(s.LeaseSeconds) * time.Second)
	return nil
}

// The third result rejects expired routes without falling back to freedom.
func (r *Registry) Lookup(inbound string) (outbound string, managed, expired bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lookup(inbound)
}

func (r *Registry) lookup(inbound string) (outbound string, managed, expired bool) {
	outbound, managed = r.bindings[inbound]
	if !managed {
		parts := strings.Split(inbound, "_")
		if len(parts) == 3 && (parts[0] == "Vless" || parts[0] == "Vmess" || parts[0] == "Trojan" || parts[0] == "Shadowsocks") {
			port, err := strconv.Atoi(parts[1])
			id, idErr := strconv.ParseInt(parts[2], 10, 64)
			if err == nil && idErr == nil && port > 0 && port <= 65535 && id > 0 {
				outbound, managed = r.entries[id]
			}
		}
	}
	return outbound, managed, managed && !time.Now().Before(r.expires)
}

// Acquire pins the selected immutable handler before a routing replacement can
// retire it. Release happens only when the outbound dispatch has finished.
func (r *Registry) Acquire(inbound string) (outbound string, managed, expired bool, release func()) {
	r.mu.Lock()
	outbound, managed, expired = r.lookup(inbound)
	if managed && !expired {
		if r.users == nil {
			r.users = make(map[string]int)
		}
		r.users[outbound]++
	}
	r.mu.Unlock()
	var once sync.Once
	release = func() {
		once.Do(func() {
			if !managed || expired {
				return
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			r.users[outbound]--
			if r.users[outbound] == 0 {
				delete(r.users, outbound)
			}
		})
	}
	return
}

func (r *Registry) CanRetire(outbound string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.users[outbound] > 0 {
		return false
	}
	for _, tag := range r.bindings {
		if tag == outbound {
			return false
		}
	}
	return true
}

func (r *Registry) Validate(s Snapshot) error {
	_, digest, err := Canonical(s)
	if err != nil {
		return err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s.Revision < r.revision || (s.Revision == r.revision && r.digest != digest) {
		return errors.New("egress revision conflict")
	}
	return nil
}

func (r *Registry) Revision() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revision
}

// Expired bindings also require explicit withdrawal before consent is revoked.
func (r *Registry) HasBindings() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.bindings) > 0
}

// Restart restoration may shorten, but must never renew, an authorization lease.
func (r *Registry) RestrictLease(until time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if until.Before(r.expires) {
		r.expires = until
	}
}
