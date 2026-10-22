package limiter

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/redis/go-redis/v9"
)

func testRedis(t *testing.T) string {
	t.Helper()
	binary, err := exec.LookPath("redis-server")
	if err != nil {
		if os.Getenv("NAHAN_REQUIRE_REDIS_TESTS") == "1" {
			t.Fatal("redis-server is required")
		}
		t.Skip("redis-server not installed")
	}
	path := filepath.Join(t.TempDir(), "redis.sock")
	cmd := exec.Command(binary, "--port", "0", "--unixsocket", path, "--unixsocketperm", "700", "--save", "", "--appendonly", "no")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 20*time.Millisecond)
		if err == nil {
			conn.Close()
			return path
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("isolated Redis did not start")
	return ""
}

func redisLimiter(t *testing.T, path, tag, scope string, limit int) (*Limiter, string) {
	t.Helper()
	l := New()
	users := []api.SubscriptionInfo{{UID: 7, Email: "subscriber", DeviceLimit: limit}}
	err := l.AddInboundLimiter(tag, 0, &users, &IPLimit{Enable: true, RedisNetwork: "unix", RedisAddr: path, Scope: scope, Timeout: 1, Expiry: 120})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.DeleteInboundLimiter(tag) })
	return l, tag + "|subscriber|7"
}

func TestAtomicIPAdmissionAcrossIndependentCores(t *testing.T) {
	path := testRedis(t)
	a, ea := redisLimiter(t, path, "core-a", "panel", 3)
	b, eb := redisLimiter(t, path, "core-b", "panel", 3)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 1; i <= 80; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l, email, tag := a, ea, "core-a"
			if i%2 == 0 {
				l, email, tag = b, eb, "core-b"
			}
			if _, _, reject := l.GetUserBucket(tag, email, fmt.Sprintf("192.0.2.%d", i)); !reject {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 3 {
		t.Fatalf("global cap bypassed or underfilled: %d", accepted.Load())
	}
	g := a.mustGlobal(t, "core-a")
	if count := g.client.ZCard(context.Background(), g.key(ea, SubscriptionInfo{})).Val(); count != 3 {
		t.Fatalf("incorrect presence count: %d", count)
	}
}

func (l *Limiter) mustGlobal(t *testing.T, tag string) *globalIPState {
	t.Helper()
	v, ok := l.InboundInfo.Load(tag)
	if !ok {
		t.Fatal("missing inbound")
	}
	return v.(*InboundInfo).GlobalIPLimit
}

func TestGlobalIPCanonicalIdentityExpiryAndScope(t *testing.T) {
	path := testRedis(t)
	a, ea := redisLimiter(t, path, "a", "panel", 1)
	b, eb := redisLimiter(t, path, "b", "panel", 1)
	admit := func(l *Limiter, tag, email, ip string, want bool) {
		t.Helper()
		_, _, reject := l.GetUserBucket(tag, email, ip)
		if reject == want {
			t.Fatalf("%s admission=%v want=%v", ip, !reject, want)
		}
	}
	admit(a, "a", ea, "::ffff:192.0.2.1", true)
	admit(b, "b", eb, "192.0.2.1", true)
	admit(b, "b", eb, "192.0.2.2", false)
	admit(a, "a", ea, "not-an-ip", false)
	admit(a, "a", ea, "fe80::1%eth0", false)
	c, ec := redisLimiter(t, path, "c", "other-panel", 1)
	admit(c, "c", ec, "192.0.2.2", true)
	g := a.mustGlobal(t, "a")
	key := g.key(ea, SubscriptionInfo{})
	// Expire just one member using Redis time; no wall-clock sleeps or client skew.
	g.client.Eval(context.Background(), `local t=redis.call('TIME');return redis.call('ZADD',KEYS[1],tonumber(t[1])*1000-1,ARGV[1])`, []string{key}, "192.0.2.1")
	admit(b, "b", eb, "192.0.2.2", true)
	if g.key(ea, SubscriptionInfo{ServiceID: 33}) != b.mustGlobal(t, "b").key("b|renamed|99", SubscriptionInfo{ServiceID: 33}) {
		t.Fatal("stable service identity was lost")
	}
	lowered := SubscriptionInfo{DeviceLimit: 1}
	if g.key(ea, lowered) != key {
		t.Fatal("limit changed the identity")
	}
}

func TestGlobalIPFailurePolicyAuthenticationAndDiagnostics(t *testing.T) {
	for _, policy := range []string{"allow", "deny"} {
		t.Run(policy, func(t *testing.T) {
			l := New()
			users := []api.SubscriptionInfo{{UID: 7, Email: "subscriber", DeviceLimit: 1}}
			config := &IPLimit{Enable: true, RedisNetwork: "unix", RedisAddr: filepath.Join(t.TempDir(), "missing"), OnError: policy}
			if err := l.AddInboundLimiter("a", 0, &users, config); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { l.DeleteInboundLimiter("a") })
			start := time.Now()
			_, _, reject := l.GetUserBucket("a", "a|subscriber|7", "192.0.2.1")
			if reject != (policy == "deny") || time.Since(start) > 1500*time.Millisecond {
				t.Fatal("failure policy or budget violated")
			}
			if _, _, reject = l.GetUserBucket("a", "a|unknown|999", "192.0.2.1"); !reject {
				t.Fatal("Redis outage bypassed authentication")
			}
			d, _ := l.GlobalIPDiagnostics("a")
			if d.Unavailable != 1 || (policy == "allow" && d.Bypassed != 1) {
				t.Fatalf("incorrect bounded diagnostics: %+v", d)
			}
		})
	}
}

func TestGlobalIPRenewalDoesNotCreateOrDeleteAnotherCoresPresence(t *testing.T) {
	path := testRedis(t)
	a, ea := redisLimiter(t, path, "a", "panel", 2)
	b, eb := redisLimiter(t, path, "b", "panel", 2)
	for _, entry := range []struct {
		l              *Limiter
		tag, email, ip string
	}{{a, "a", ea, "192.0.2.1"}, {b, "b", eb, "192.0.2.2"}} {
		if _, _, reject := entry.l.GetUserBucket(entry.tag, entry.email, entry.ip); reject {
			t.Fatal("initial admission failed")
		}
	}
	g := a.mustGlobal(t, "a")
	key := g.key(ea, SubscriptionInfo{})
	ctx := context.Background()
	before := g.client.ZScore(ctx, key, "192.0.2.1").Val()
	a.TouchOnline("a", ea, "::ffff:192.0.2.1")
	a.GetOnlineDevice("a")
	if g.client.ZScore(ctx, key, "192.0.2.1").Val() < before || g.client.ZCard(ctx, key).Val() != 2 {
		t.Fatal("renewal shortened a lease or erased peer presence")
	}
	g.client.ZRem(ctx, key, "192.0.2.1")
	a.GetOnlineDevice("a")
	if g.client.ZCard(ctx, key).Val() != 1 {
		t.Fatal("renewal invented an absent grant")
	}
	a.DeleteInboundLimiter("a")
	if g2 := b.mustGlobal(t, "b"); g2.client.ZCard(ctx, key).Val() != 1 {
		t.Fatal("disconnect removed another core's presence")
	}
}

func TestGlobalIPConfigurationAndBoundedOversizedKey(t *testing.T) {
	for _, config := range []IPLimit{{Enable: true}, {Enable: true, RedisAddr: "unused", OnError: "sometimes"}, {Enable: true, RedisAddr: "unused", Expiry: 601}} {
		if _, err := newGlobalIP(&config); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	path := testRedis(t)
	l, email := redisLimiter(t, path, "a", "panel", 1)
	g := l.mustGlobal(t, "a")
	members := make([]redis.Z, maxGlobalIPs+1)
	for i := range members {
		members[i] = redis.Z{Score: float64(time.Now().Add(time.Minute).UnixMilli()), Member: fmt.Sprint(i)}
	}
	if err := g.client.ZAdd(context.Background(), g.key(email, SubscriptionInfo{}), members...).Err(); err != nil {
		t.Fatal(err)
	}
	if _, _, reject := l.GetUserBucket("a", email, "192.0.2.1"); !reject {
		t.Fatal("oversized key failed open")
	}
}
