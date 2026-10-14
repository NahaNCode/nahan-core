package limiter

import (
	"github.com/NahaNCode/nahan-core/api"
	"testing"
)

func TestInfrastructureLimiterDoesNotOverwriteCustomerOrReportBillingIdentity(t *testing.T) {
	l := New()
	users := []api.SubscriptionInfo{{UID: 7, Email: "customer", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("qa", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	email := "nahan-egress/route/source/1"
	if err := l.AddInfrastructureUser("qa", email); err != nil {
		t.Fatal(err)
	}
	if err := l.AddInfrastructureUser("qa", email); err == nil {
		t.Fatal("duplicate infrastructure identity accepted")
	}
	for _, user := range []string{email, "qa|customer|7"} {
		if _, _, reject := l.GetUserBucket("qa", user, "127.0.0.1"); reject {
			t.Fatal("user rejected")
		}
		l.TouchOnline("qa", user, "127.0.0.1")
	}
	online, err := l.GetOnlineDevice("qa")
	if err != nil || len(*online) != 1 || (*online)[0].UID != 7 {
		t.Fatal("infrastructure counted as customer", online, err)
	}
	l.RemoveUser("qa", email)
	if _, _, reject := l.GetUserBucket("qa", "qa|customer|7", "127.0.0.1"); reject {
		t.Fatal("customer limiter changed")
	}
	if err := l.AddInfrastructureUser("qa", "customer"); err == nil {
		t.Fatal("customer namespace accepted")
	}
}
