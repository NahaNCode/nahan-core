package limiter

import (
	"github.com/NahaNCode/nahan-core/api"
	"golang.org/x/time/rate"
	"testing"
)

func TestServiceLimitsSharedAcrossAuthorizedInbounds(t *testing.T) {
	l := New()
	users := []api.SubscriptionInfo{{UID: 10, Email: "service-10@nahan.invalid", SpeedLimit: 1000, DeviceLimit: 1}}
	for _, tag := range []string{"a", "b"} {
		if err := l.AddInboundLimiter(tag, 0, &users, nil); err != nil {
			t.Fatal(err)
		}
	}
	a, limited, reject := l.GetUserBucket("a", "a|service-10@nahan.invalid|10", "127.0.0.1")
	if !limited || reject {
		t.Fatal("authorized service rejected")
	}
	b, _, reject := l.GetUserBucket("b", "b|service-10@nahan.invalid|10", "127.0.0.1")
	if reject || a != b {
		t.Fatal("service received independent speed buckets")
	}
	if _, _, reject = l.GetUserBucket("b", "b|service-10@nahan.invalid|10", "127.0.0.2"); !reject {
		t.Fatal("IP limit bypassed using another inbound")
	}
	l.RemoveUser("a", "a|service-10@nahan.invalid|10")
	if _, _, reject = l.GetUserBucket("a", "a|service-10@nahan.invalid|10", "127.0.0.1"); !reject {
		t.Fatal("revoked assignment accepted")
	}
	if bucket, _, reject := l.GetUserBucket("b", "b|service-10@nahan.invalid|10", "127.0.0.1"); reject || bucket != b {
		t.Fatal("other authorized assignment disturbed")
	}
	if _, _, reject = l.GetUserBucket("missing", "service-10", ""); !reject {
		t.Fatal("unknown inbound must fail closed")
	}
}

func TestServiceRateDoesNotDependOnFirstInboundOrLastUpdate(t *testing.T) {
	l := New()
	users := []api.SubscriptionInfo{{UID: 10, Email: "service", SpeedLimit: 1000}}
	l.AddInboundLimiter("fast", 0, &users, nil)
	first, _, _ := l.GetUserBucket("fast", "fast|service|10", "127.0.0.1")
	l.AddInboundLimiter("slow", 200, &users, nil)
	second, _, _ := l.GetUserBucket("slow", "slow|service|10", "127.0.0.1")
	if first != second || first.Limit() != 200 {
		t.Fatal("first inbound bypassed the lower assignment ceiling")
	}
	users[0].SpeedLimit = 2000
	l.UpdateInboundLimiter("fast", &users)
	if first.Limit() != 200 {
		t.Fatal("unrelated faster update raised the shared limit")
	}
	l.DeleteInboundLimiter("slow")
	if first.Limit() != 2000 {
		t.Fatal("removed assignment still limits the surviving service")
	}
	users[0].SpeedLimit = 0
	l.UpdateInboundLimiter("fast", &users)
	if first.Limit() != rate.Inf {
		t.Fatal("existing stream kept an orphaned limited bucket")
	}
	users[0].SpeedLimit = 500
	l.UpdateInboundLimiter("fast", &users)
	third, _, _ := l.GetUserBucket("fast", "fast|service|10", "127.0.0.1")
	if first != third || first.Limit() != 500 {
		t.Fatal("limit change split the service bucket")
	}
}

func TestLocalIPCanonicalizationAcrossInbounds(t *testing.T) {
	l := New()
	users := []api.SubscriptionInfo{{UID: 1, Email: "subscriber", DeviceLimit: 1}}
	l.AddInboundLimiter("a", 0, &users, nil)
	for _, ip := range []string{"192.0.2.1", "::ffff:192.0.2.1"} {
		if _, _, reject := l.GetUserBucket("a", "a|subscriber|1", ip); reject {
			t.Fatal("same canonical address consumed another slot")
		}
	}
	if _, _, reject := l.GetUserBucket("a", "a|subscriber|1", "192.0.2.2"); !reject {
		t.Fatal("local cap bypassed")
	}
}

func TestInitiallyUnlimitedStreamRetainsBucketWhenLimitIntroduced(t *testing.T) {
	l := New()
	users := []api.SubscriptionInfo{{UID: 1, Email: "subscriber"}}
	if err := l.AddInboundLimiter("a", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	old, limited, reject := l.GetUserBucket("a", "a|subscriber|1", "127.0.0.1")
	if reject || limited || old == nil || old.Limit() != rate.Inf {
		t.Fatal("unlimited admission lacks persistent gate")
	}
	users[0].SpeedLimit = 500
	if err := l.UpdateInboundLimiter("a", &users); err != nil {
		t.Fatal(err)
	}
	current, limited, reject := l.GetUserBucket("a", "a|subscriber|1", "127.0.0.1")
	if reject || !limited || current != old || old.Limit() != 500 {
		t.Fatal("existing stream bypassed introduced limit")
	}
}
