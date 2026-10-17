package xdispatcher

import (
	"bytes"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

func TestNativeReaderAndWriterRefreshActivity(t *testing.T) {
	calls := 0
	writer := &activityWriter{Writer: buf.NewWriter(&bytes.Buffer{}), touch: func() { calls++ }}
	reader := &activityReader{Reader: buf.NewReader(bytes.NewBufferString("uplink")), activity: writer}
	mb, err := reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() || calls != 1 {
		t.Fatal("native uplink did not refresh activity")
	}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("activity was not throttled")
	}
	writer.lastTouch = time.Now().Add(-11 * time.Second)
	b := buf.New()
	b.Write([]byte("downlink"))
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("native downlink did not refresh activity")
	}
}

func TestActivityWrappersStopInvalidLease(t *testing.T) {
	valid, stopped := true, 0
	output := &bytes.Buffer{}
	writer := &activityWriter{Writer: buf.NewWriter(output), valid: func() bool { return valid }, stop: func() { stopped++ }}
	reader := &activityReader{Reader: buf.NewReader(bytes.NewBufferString("uplink")), activity: writer}
	valid = false
	b := buf.New()
	b.Write([]byte("forbidden"))
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err == nil || output.Len() != 0 {
		t.Fatal("invalid lease forwarded traffic")
	}
	if mb, err := reader.ReadMultiBuffer(); err == nil || len(mb) != 0 {
		t.Fatal("invalid lease reader forwarded traffic")
	}
	if stopped != 2 {
		t.Fatal("invalid lease did not interrupt streams")
	}
}
