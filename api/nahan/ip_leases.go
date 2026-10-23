package nahan

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type ipKey struct {
	ID int    `json:"subscriptionId"`
	IP string `json:"ip"`
}
type ipLeases struct {
	mu, renewMu         sync.Mutex
	entries             map[ipKey]*deviceLease
	requests            chan struct{}
	unavailable, denied atomic.Uint64
	renewCursor         int
}

func (c *APIClient) IPLeaseDiagnostics() (unavailable, denied uint64) {
	return c.ips.unavailable.Load(), c.ips.denied.Load()
}

func canonicalLeaseIP(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	return a.Unmap().String(), true
}

func (c *APIClient) AdmitIP(id int, ip string) bool {
	ip, ok := canonicalLeaseIP(ip)
	if !ok || id <= 0 || c.protocol != "nahan-v1" {
		return false
	}
	key := ipKey{id, ip}
	c.ips.mu.Lock()
	if c.ips.entries == nil {
		c.ips.entries = make(map[ipKey]*deviceLease)
	}
	e := c.ips.entries[key]
	now := time.Now()
	if e != nil {
		e.active = now
		if now.Before(e.expires) {
			c.ips.mu.Unlock()
			return true
		}
		if pending := e.pending; pending != nil {
			c.ips.mu.Unlock()
			<-pending
			return c.validIP(key)
		}
		if now.Before(e.retryAt) {
			c.ips.mu.Unlock()
			return false
		}
	} else {
		if len(c.ips.entries) >= 65536 {
			c.ips.mu.Unlock()
			return false
		}
		e = &deviceLease{active: now}
		c.ips.entries[key] = e
	}
	e.pending = make(chan struct{})
	c.ips.mu.Unlock()
	_ = c.fetchIPLeases(context.Background(), []ipKey{key}, false)
	c.finishIPRequests([]ipKey{key})
	return c.validIP(key)
}

func (c *APIClient) validIP(key ipKey) bool {
	c.ips.mu.Lock()
	defer c.ips.mu.Unlock()
	e := c.ips.entries[key]
	return e != nil && time.Now().Before(e.expires)
}

func (c *APIClient) ValidIP(id int, ip string) bool {
	ip, ok := canonicalLeaseIP(ip)
	return ok && id > 0 && c.validIP(ipKey{id, ip})
}

func (c *APIClient) TouchIP(id int, ip string) {
	ip, ok := canonicalLeaseIP(ip)
	if !ok {
		return
	}
	c.ips.mu.Lock()
	defer c.ips.mu.Unlock()
	if e := c.ips.entries[ipKey{id, ip}]; e != nil {
		e.active = time.Now()
	}
}

func (c *APIClient) finishIPRequests(keys []ipKey) {
	c.ips.mu.Lock()
	defer c.ips.mu.Unlock()
	for _, key := range keys {
		e := c.ips.entries[key]
		e.retryAt = time.Now().Add(2 * time.Second)
		close(e.pending)
		e.pending = nil
	}
}

func (c *APIClient) RenewIPs() error {
	c.ips.renewMu.Lock()
	defer c.ips.renewMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.ips.mu.Lock()
	var keys []ipKey
	for key, e := range c.ips.entries {
		if e.pending != nil {
			continue
		}
		if time.Since(e.active) >= 120*time.Second {
			delete(c.ips.entries, key)
		} else {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ID == keys[j].ID {
			return keys[i].IP < keys[j].IP
		}
		return keys[i].ID < keys[j].ID
	})
	if len(keys) > 0 {
		offset := c.ips.renewCursor % len(keys)
		keys = append(keys[offset:], keys[:offset]...)
	}
	c.ips.mu.Unlock()
	var failures []error
	for start := 0; start < len(keys); start += 512 {
		if ctx.Err() != nil {
			failures = append(failures, errors.New("IP renewal budget exhausted"))
			break
		}
		end := start + 512
		if end > len(keys) {
			end = len(keys)
		}
		var batch []ipKey
		c.ips.mu.Lock()
		for _, key := range keys[start:end] {
			if e := c.ips.entries[key]; e != nil && e.pending == nil {
				e.pending = make(chan struct{})
				batch = append(batch, key)
			}
		}
		c.ips.mu.Unlock()
		if len(batch) == 0 {
			continue
		}
		if err := c.fetchIPLeases(ctx, batch, true); err != nil {
			failures = append(failures, err)
		}
		c.finishIPRequests(batch)
		c.ips.mu.Lock()
		c.ips.renewCursor = (c.ips.renewCursor + end - start) % len(keys)
		c.ips.mu.Unlock()
	}
	return errors.Join(failures...)
}

func (c *APIClient) fetchIPLeases(parent context.Context, keys []ipKey, renew bool) (result error) {
	defer func() {
		if result != nil {
			c.ips.unavailable.Add(1)
		}
	}()
	c.ips.mu.Lock()
	if c.ips.requests == nil {
		c.ips.requests = make(chan struct{}, 8)
	}
	requests := c.ips.requests
	c.ips.mu.Unlock()
	select {
	case requests <- struct{}{}:
		defer func() { <-requests }()
	default:
		return errors.New("IP lease request capacity reached")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	response, err := c.client.Clone().SetRetryCount(0).R().SetContext(ctx).SetBody(struct {
		Entries []ipKey `json:"entries"`
		Renew   bool    `json:"renew"`
	}{keys, renew}).Post(c.path("ip-leases"))
	if err != nil || response.StatusCode() != 200 {
		return errors.New("IP lease coordinator unavailable")
	}
	var reply struct {
		LeaseSeconds int `json:"leaseSeconds"`
		Grants       []struct {
			ID      int    `json:"subscriptionId"`
			IP      string `json:"ip"`
			Expires int64  `json:"expiresAt"`
		} `json:"grants"`
		Denied []ipKey `json:"denied"`
	}
	if json.Unmarshal(response.Body(), &reply) != nil || reply.LeaseSeconds != 120 {
		return errors.New("invalid IP lease response")
	}
	requested, seen := make(map[ipKey]bool), make(map[ipKey]bool)
	expiry := make(map[ipKey]time.Time)
	now := time.Now()
	for _, key := range keys {
		requested[key] = true
	}
	for _, grant := range reply.Grants {
		ip, ok := canonicalLeaseIP(grant.IP)
		key := ipKey{grant.ID, ip}
		until := time.Unix(grant.Expires, 0)
		if !ok || !requested[key] || seen[key] || !until.After(now) || until.After(now.Add(120*time.Second)) {
			return errors.New("invalid IP lease grant")
		}
		seen[key] = true
		expiry[key] = until
	}
	for _, denied := range reply.Denied {
		ip, ok := canonicalLeaseIP(denied.IP)
		key := ipKey{denied.ID, ip}
		if !ok || !requested[key] || seen[key] {
			return errors.New("invalid IP lease denial")
		}
		seen[key] = true
	}
	if len(seen) != len(requested) {
		return errors.New("incomplete IP lease response")
	}
	c.ips.mu.Lock()
	defer c.ips.mu.Unlock()
	for _, key := range keys {
		if e := c.ips.entries[key]; e != nil {
			e.expires = expiry[key]
		}
	}
	c.ips.denied.Add(uint64(len(reply.Denied)))
	return nil
}
