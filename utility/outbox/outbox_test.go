package outbox

import (
	"errors"
	"github.com/NahaNCode/nahan-core/api"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReplayAfterRestartAndLostAcknowledgment(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	rows := []api.SubscriptionTraffic{{UID: 101, Upload: 12}, {UID: 102, Download: 34}}
	if err := q.Enqueue(rows); err != nil {
		t.Fatal(err)
	}
	var original Report
	if err := q.Flush(func(r Report) error { original = r; return errors.New("ack lost") }); err == nil {
		t.Fatal("expected failure")
	}
	q, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := q.Flush(func(r Report) error {
		calls++
		if r.ID != original.ID || len(r.Traffic) != 2 || r.Traffic[0].UID != 101 || r.Traffic[1].Download != 34 {
			t.Fatal("replay changed service or payload")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.Flush(func(Report) error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("acknowledged report remained queued")
	}
}

func TestInvalidStorageDoesNotAcceptTraffic(t *testing.T) {
	q := &Queue{dir: t.TempDir() + "/missing"}
	if err := q.Enqueue([]api.SubscriptionTraffic{{UID: 1, Upload: 1}}); err == nil {
		t.Fatal("accepted unpersisted report")
	}
}

func TestBlockedFlushDoesNotBlockDurableEnqueue(t *testing.T) {
	q, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rows := []api.SubscriptionTraffic{{UID: 1, Upload: 100}}
	if err = q.Enqueue(rows); err != nil {
		t.Fatal(err)
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- q.Flush(func(Report) error { close(started); <-release; return errors.New("ack lost") })
	}()
	<-started
	defer func() { close(release); <-done }()
	enqueued := make(chan error, 1)
	go func() { enqueued <- q.Enqueue(rows) }()
	select {
	case err := <-enqueued:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("network flush holds persistence lock")
	}
	if n, err := q.Pending(); err != nil || n != 2 {
		t.Fatal("reports lost", n, err)
	}
}

func TestByteLimitRetainsReportsAndAllowsRecovery(t *testing.T) {
	q, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	q.maxBytes = 1
	rows := []api.SubscriptionTraffic{{UID: 1, Upload: 100}}
	if q.Enqueue(rows) == nil {
		t.Fatal("byte limit not enforced")
	}
	if n, _ := q.Pending(); n != 0 {
		t.Fatal("partial report published")
	}
	q.maxBytes = MaxBytes
	if err = q.Enqueue(rows); err != nil {
		t.Fatal(err)
	}
	q.maxBytes = 1
	if err = q.Flush(func(r Report) error { return nil }); err != nil {
		t.Fatal("full queue cannot drain", err)
	}
	if n, _ := q.Pending(); n != 0 {
		t.Fatal("ack not removed")
	}
}

func TestOversizedExistingReportRetained(t *testing.T) {
	q, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(q.dir, "old.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(MaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = q.Flush(func(Report) error { t.Fatal("oversized report sent"); return nil }); err == nil {
		t.Fatal("oversized report accepted")
	}
	if _, err = os.Stat(p); err != nil {
		t.Fatal("unacknowledged report deleted", err)
	}
}
