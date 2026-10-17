package limiter

import (
	"sync"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/api"
)

func TestOnlineActivitySurvivesReportsAndExpires(t *testing.T) {
	l := New()
	users := []api.SubscriptionInfo{{UID: 7, Email: "test"}}
	if err := l.AddInboundLimiter("node", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	email := "node|test|7"
	l.GetUserBucket("node", email, "192.0.2.1")
	for i := 0; i < 3; i++ {
		rows, err := l.GetOnlineDevice("node")
		if err != nil || len(*rows) != 1 {
			t.Fatalf("report lost online activity: %v", err)
		}
	}
	v, _ := l.InboundInfo.Load("node")
	ips, _ := v.(*InboundInfo).SubscriptionOnlineIP.Load(email)
	ips.(*sync.Map).Store("192.0.2.1", onlineActivity{uid: 7, at: time.Now().Add(-3 * time.Minute)})
	rows, _ := l.GetOnlineDevice("node")
	if len(*rows) != 0 {
		t.Fatal("stale activity counted")
	}
	l.TouchOnline("node", email, "192.0.2.1")
	rows, _ = l.GetOnlineDevice("node")
	if len(*rows) != 1 {
		t.Fatal("existing stream activity not counted")
	}
}
