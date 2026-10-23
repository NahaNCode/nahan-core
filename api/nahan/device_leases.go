package nahan

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NahaNCode/nahan-core/api"
)

type deviceLease struct {
	expires time.Time
	active  time.Time
	pending chan struct{}
	retryAt time.Time
}

type deviceCredential struct {
	fingerprint [32]byte
	email       string
}

type deviceLeases struct {
	mu          sync.Mutex
	renewMu     sync.Mutex
	entries     map[int]*deviceLease
	requests    chan struct{}
	unavailable atomic.Uint64
	saturated   atomic.Uint64
	denied      atomic.Uint64
	renewCursor int
}

type DeviceLeaseDiagnostics struct {
	Unavailable uint64 `json:"unavailable"`
	Saturated   uint64 `json:"saturated"`
	Denied      uint64 `json:"denied"`
}

func (c *APIClient) DeviceLeaseDiagnostics() DeviceLeaseDiagnostics {
	return DeviceLeaseDiagnostics{c.devices.unavailable.Load(), c.devices.saturated.Load(), c.devices.denied.Load()}
}

func (c *APIClient) DeviceGate() api.DeviceGate {
	if c.protocol != "nahan-v1" {
		return nil
	}
	return c
}

func (c *APIClient) AdmitDevice(id int) bool {
	if id <= 0 {
		return false
	}
	c.devices.mu.Lock()
	if c.devices.entries == nil {
		c.devices.entries = make(map[int]*deviceLease)
	}
	entry := c.devices.entries[id]
	if entry != nil {
		pending := entry.pending
		entry.active = time.Now()
		if time.Now().Before(entry.expires) {
			c.devices.mu.Unlock()
			return true
		}
		if pending != nil {
			c.devices.mu.Unlock()
			<-pending
			return c.ValidDevice(id)
		}
		if time.Now().Before(entry.retryAt) {
			c.devices.mu.Unlock()
			return false
		}
	} else {
		entry = &deviceLease{active: time.Now()}
		c.devices.entries[id] = entry
	}
	entry.pending = make(chan struct{})
	c.devices.mu.Unlock()
	_ = c.fetchDeviceLeases(context.Background(), []int{id})
	c.finishDeviceRequests([]int{id})
	return c.ValidDevice(id)
}

func (c *APIClient) finishDeviceRequests(ids []int) {
	c.devices.mu.Lock()
	defer c.devices.mu.Unlock()
	for _, id := range ids {
		entry := c.devices.entries[id]
		entry.retryAt = time.Now().Add(2 * time.Second)
		close(entry.pending)
		entry.pending = nil
	}
}

func (c *APIClient) ValidDevice(id int) bool {
	c.devices.mu.Lock()
	defer c.devices.mu.Unlock()
	e := c.devices.entries[id]
	return e != nil && time.Now().Before(e.expires)
}

func (c *APIClient) TouchDevice(id int) {
	c.devices.mu.Lock()
	defer c.devices.mu.Unlock()
	if e := c.devices.entries[id]; e != nil {
		e.active = time.Now()
	}
}

func (c *APIClient) RenewDevices() error {
	c.devices.renewMu.Lock()
	defer c.devices.renewMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.devices.mu.Lock()
	var ids []int
	for id, e := range c.devices.entries {
		if e.pending != nil {
			continue
		}
		if time.Since(e.active) >= 120*time.Second {
			delete(c.devices.entries, id)
		} else {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	if len(ids) > 0 {
		offset := c.devices.renewCursor % len(ids)
		ids = append(ids[offset:], ids[:offset]...)
	}
	c.devices.mu.Unlock()
	var failures []error
	for start := 0; start < len(ids); start += 512 {
		if ctx.Err() != nil {
			failures = append(failures, errors.New("device renewal budget exhausted"))
			break
		}
		end := start + 512
		if end > len(ids) {
			end = len(ids)
		}
		var batch []int
		c.devices.mu.Lock()
		for _, id := range ids[start:end] {
			if entry := c.devices.entries[id]; entry != nil && entry.pending == nil {
				entry.pending = make(chan struct{})
				batch = append(batch, id)
			}
		}
		c.devices.mu.Unlock()
		if len(batch) == 0 {
			continue
		}
		if err := c.fetchDeviceLeases(ctx, batch); err != nil {
			failures = append(failures, err)
		}
		c.finishDeviceRequests(batch)
		c.devices.mu.Lock()
		c.devices.renewCursor = (c.devices.renewCursor + end - start) % len(ids)
		c.devices.mu.Unlock()
	}
	return errors.Join(failures...)
}

func (c *APIClient) fetchDeviceLeases(parent context.Context, ids []int) (result error) {
	defer func() {
		if result != nil {
			c.devices.unavailable.Add(1)
		}
	}()
	c.devices.mu.Lock()
	if c.devices.requests == nil {
		c.devices.requests = make(chan struct{}, 8)
	}
	requests := c.devices.requests
	c.devices.mu.Unlock()
	select {
	case requests <- struct{}{}:
		defer func() { <-requests }()
	default:
		c.devices.saturated.Add(1)
		return errors.New("device lease request capacity reached")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	res, err := c.client.Clone().SetRetryCount(0).R().SetContext(ctx).
		SetBody(struct {
			IDs []int `json:"deviceIds"`
		}{ids}).Post(c.path("device-leases"))
	if err != nil {
		return errors.New("device lease request failed")
	}
	if res.StatusCode() != 200 {
		return errors.New("device lease request rejected")
	}
	var reply struct {
		LeaseSeconds int `json:"leaseSeconds"`
		Grants       []struct {
			ID      int   `json:"deviceId"`
			Expires int64 `json:"expiresAt"`
		} `json:"grants"`
		Denied []int `json:"denied"`
	}
	if json.Unmarshal(res.Body(), &reply) != nil || reply.LeaseSeconds != 120 {
		return errors.New("invalid device lease response")
	}
	requested, seen := make(map[int]bool), make(map[int]bool)
	expires := make(map[int]time.Time)
	now := time.Now()
	for _, id := range ids {
		requested[id] = true
	}
	for _, grant := range reply.Grants {
		until := time.Unix(grant.Expires, 0)
		if !requested[grant.ID] || seen[grant.ID] || !until.After(now) || until.After(now.Add(120*time.Second)) {
			return errors.New("invalid device lease grant")
		}
		seen[grant.ID], expires[grant.ID] = true, until
	}
	for _, id := range reply.Denied {
		if !requested[id] || seen[id] {
			return errors.New("invalid device lease denial")
		}
		seen[id] = true
	}
	if len(seen) != len(requested) {
		return errors.New("incomplete device lease response")
	}
	c.devices.mu.Lock()
	defer c.devices.mu.Unlock()
	for _, id := range ids {
		if e := c.devices.entries[id]; e != nil {
			e.expires = expires[id]
		}
	}
	c.devices.denied.Add(uint64(len(reply.Denied)))
	return nil
}
