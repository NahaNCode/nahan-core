// Package outbox persists immutable traffic reports until the panel acknowledges them.
package outbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/google/uuid"
)

type Report struct {
	ID      string                    `json:"id"`
	Traffic []api.SubscriptionTraffic `json:"traffic"`
}

type Queue struct {
	dir string
	mu  sync.Mutex
}

func Open(dir string) (*Queue, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Queue{dir: dir}, nil
}

func (q *Queue) syncDir() error {
	d, err := os.Open(q.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (q *Queue) Pending() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n, nil
}

func (q *Queue) Enqueue(traffic []api.SubscriptionTraffic) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(traffic) == 0 {
		return nil
	}
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	if len(entries) >= 10000 {
		return fmt.Errorf("traffic outbox full; retaining live counters")
	}
	r := Report{ID: uuid.NewString(), Traffic: traffic}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(q.dir, ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(q.dir, r.ID+".json")); err != nil {
		return err
	}
	return q.syncDir()
}

// Flush stops at the first error, retaining the original ID and payload for replay.
func (q *Queue) Flush(send func(Report) error) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(q.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var r Report
		if err = json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("invalid outbox report: %w", err)
		}
		if r.ID+".json" != entry.Name() || len(r.Traffic) == 0 {
			return fmt.Errorf("invalid outbox identity")
		}
		if err = send(r); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		if err = q.syncDir(); err != nil {
			return err
		}
	}
	return nil
}
