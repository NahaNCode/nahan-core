package limiter

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const maxGlobalIPs = 4096
const globalRenewBatch = 256

// One key and Redis time make admission atomic across hosts and cluster slots.
// A corrupt oversized key is never scanned or silently treated as a grant.
const globalIPLua = `
local size = redis.call('ZCARD', KEYS[1])
if size > 4096 then return -1 end
local clock = redis.call('TIME')
local now = tonumber(clock[1])*1000 + math.floor(tonumber(clock[2])/1000)
local ttl = tonumber(ARGV[3])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local count = redis.call('ZCARD', KEYS[1])
local previous = tonumber(redis.call('ZSCORE', KEYS[1], ARGV[1]) or '0')
if count > limit then return 0 end
if previous == 0 and (ARGV[4] == 'renew' or count >= limit) then return 0 end
redis.call('ZADD', KEYS[1], math.max(previous, now + ttl), ARGV[1])
if redis.call('PTTL', KEYS[1]) < ttl then redis.call('PEXPIRE', KEYS[1], ttl) end
return 1
`

var globalIPScript = redis.NewScript(globalIPLua)

type globalIPState struct {
	client                                 *redis.Client
	config                                 IPLimit
	allowed, denied, unavailable, bypassed atomic.Uint64
	renewCursor                            atomic.Uint64
	renewDeferred                          atomic.Uint64
}

type IPLimitDiagnostics struct {
	Allowed       uint64 `json:"allowed"`
	Denied        uint64 `json:"denied"`
	Unavailable   uint64 `json:"unavailable"`
	Bypassed      uint64 `json:"bypassed"`
	RenewDeferred uint64 `json:"renewDeferred"`
}

func (l *Limiter) GlobalIPDiagnostics(tag string) (IPLimitDiagnostics, bool) {
	v, ok := l.InboundInfo.Load(tag)
	if !ok || v.(*InboundInfo).GlobalIPLimit == nil {
		return IPLimitDiagnostics{}, false
	}
	g := v.(*InboundInfo).GlobalIPLimit
	return IPLimitDiagnostics{g.allowed.Load(), g.denied.Load(), g.unavailable.Load(), g.bypassed.Load(), g.renewDeferred.Load()}, true
}

func canonicalIP(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	return a.Unmap().String(), true
}

func newGlobalIP(config *IPLimit) (*globalIPState, error) {
	if config == nil || !config.Enable {
		return nil, nil
	}
	c := *config
	if c.Timeout == 0 {
		c.Timeout = 1
	}
	if c.Expiry == 0 {
		c.Expiry = 120
	}
	if c.OnError == "" {
		c.OnError = "allow"
	}
	if c.Scope == "" {
		c.Scope = "legacy"
	}
	if c.RedisAddr == "" || c.Timeout < 1 || c.Timeout > 5 || c.Expiry < 5 || c.Expiry > 600 ||
		(c.OnError != "allow" && c.OnError != "deny") || len(c.Scope) > 128 ||
		strings.ContainsAny(c.Scope, "{}\r\n\x00") ||
		(c.RedisNetwork != "" && c.RedisNetwork != "tcp" && c.RedisNetwork != "unix") {
		return nil, fmt.Errorf("invalid global IP limiter configuration")
	}
	budget := time.Duration(c.Timeout) * time.Second
	opts := &redis.Options{Network: c.RedisNetwork, Addr: c.RedisAddr, Username: c.RedisUsername,
		Password: c.RedisPassword, DB: c.RedisDB, MaxRetries: -1, DialTimeout: budget,
		ReadTimeout: budget, WriteTimeout: budget, PoolTimeout: budget, PoolSize: 8, MaxActiveConns: 8,
		ContextTimeoutEnabled: true}
	if c.RedisTLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.RedisServerName}
	}
	return &globalIPState{client: redis.NewClient(opts), config: c}, nil
}

func (g *globalIPState) key(email string, user SubscriptionInfo) string {
	identity := serviceKey(email)
	if user.ServiceID > 0 {
		identity = fmt.Sprintf("service:%d", user.ServiceID)
	}
	digest := sha256.Sum256([]byte(g.config.Scope + "\x00" + identity))
	return fmt.Sprintf("nahan:ip:v2:{%x}", digest)
}

func (g *globalIPState) args(ip string, limit int, renew bool) []interface{} {
	mode := "admit"
	if renew {
		mode = "renew"
	}
	return []interface{}{ip, limit, g.config.Expiry * 1000, mode}
}

func (g *globalIPState) admit(email string, user SubscriptionInfo, ip string) (allowed, coordinated bool) {
	if user.DeviceLimit <= 0 {
		return true, false
	}
	if user.DeviceLimit > maxGlobalIPs {
		g.denied.Add(1)
		return false, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(g.config.Timeout)*time.Second)
	defer cancel()
	n, err := globalIPScript.Run(ctx, g.client, []string{g.key(email, user)}, g.args(ip, user.DeviceLimit, false)...).Int()
	if err != nil {
		g.unavailable.Add(1)
		if g.config.OnError == "allow" {
			g.bypassed.Add(1)
			return true, false
		}
		return false, false
	}
	if n != 1 {
		g.denied.Add(1)
		return false, true
	}
	g.allowed.Add(1)
	return true, true
}

type ipRenewal struct {
	key, ip string
	limit   int
}

// Renewal uses the existing online-report cadence, not packet-path I/O or an
// unbounded goroutine per connection. It cannot admit an expired/absent member.
func (g *globalIPState) renew(inbound *InboundInfo) {
	var entries []ipRenewal
	inbound.SubscriptionOnlineIP.Range(func(email, value interface{}) bool {
		u, ok := inbound.SubscriptionInfo.Load(email)
		if !ok {
			return true
		}
		user := u.(SubscriptionInfo)
		if user.DeviceID > 0 || user.DeviceLimit <= 0 || user.DeviceLimit > maxGlobalIPs {
			return true
		}
		value.(*sync.Map).Range(func(k, v interface{}) bool {
			ip, ok := k.(string)
			if ok && time.Since(v.(onlineActivity).at) < 120*time.Second {
				entries = append(entries, ipRenewal{g.key(email.(string), user), ip, user.DeviceLimit})
			}
			return true
		})
		return true
	})
	g.renewEntries(entries)
}

func (g *globalIPState) renewEntries(entries []ipRenewal) {
	if len(entries) == 0 {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].key == entries[j].key {
			return entries[i].ip < entries[j].ip
		}
		return entries[i].key < entries[j].key
	})
	start := int(g.renewCursor.Load() % uint64(len(entries)))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(g.config.Timeout)*time.Second)
	defer cancel()
	completed := 0
	for completed < len(entries) && ctx.Err() == nil {
		count := len(entries) - completed
		if count > globalRenewBatch {
			count = globalRenewBatch
		}
		pipe := g.client.Pipeline()
		for i := 0; i < count; i++ {
			e := entries[(start+completed+i)%len(entries)]
			pipe.Eval(ctx, globalIPLua, []string{e.key}, g.args(e.ip, e.limit, true)...)
		}
		_, err := pipe.Exec(ctx)
		completed += count
		if err != nil {
			g.unavailable.Add(1)
			break
		}
	}
	g.renewCursor.Add(uint64(completed))
	g.renewDeferred.Store(uint64(len(entries) - completed))
}
