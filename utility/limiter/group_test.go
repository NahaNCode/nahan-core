package limiter

import (
	"github.com/NahaNCode/nahan-core/api"
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
