package controller

import (
	"sync/atomic"
	"testing"
)

type testCounter struct{ value int64 }

func (c *testCounter) Value() int64      { return atomic.LoadInt64(&c.value) }
func (c *testCounter) Set(v int64) int64 { return atomic.SwapInt64(&c.value, v) }
func (c *testCounter) Add(v int64) int64 { return atomic.AddInt64(&c.value, v) - v }

func TestConsumePreservesTrafficArrivingAfterSnapshot(t *testing.T) {
	c := &testCounter{value: 100}
	snapshot := trafficSnapshot{counter: c, value: c.Value()}
	c.Add(37)
	consumeTraffic([]trafficSnapshot{snapshot})
	if c.Value() != 37 {
		t.Fatalf("new traffic lost: %d", c.Value())
	}
}
