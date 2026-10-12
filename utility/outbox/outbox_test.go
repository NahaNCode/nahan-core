package outbox

import (
	"errors"
	"github.com/NahaNCode/nahan-core/api"
	"testing"
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
