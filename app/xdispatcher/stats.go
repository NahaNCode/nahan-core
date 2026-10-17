package xdispatcher

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
	"io"
	"sync"
	"time"
)

type activityWriter struct {
	buf.Writer
	touch     func()
	valid     func() bool
	stop      func()
	mu        sync.Mutex
	lastTouch time.Time
}

func (w *activityWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if !w.check() {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	if !mb.IsEmpty() {
		w.mark()
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *activityWriter) check() bool {
	if w.valid != nil && !w.valid() {
		if w.stop != nil {
			w.stop()
		}
		return false
	}
	return true
}

func (w *activityWriter) mark() {
	if w.touch == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if time.Since(w.lastTouch) >= 10*time.Second {
		w.touch()
		w.lastTouch = time.Now()
	}
}

type activityReader struct {
	buf.Reader
	activity *activityWriter
}

func (r *activityReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if !r.activity.check() {
		return nil, io.ErrClosedPipe
	}
	mb, err := r.Reader.ReadMultiBuffer()
	if !r.activity.check() {
		buf.ReleaseMulti(mb)
		return nil, io.ErrClosedPipe
	}
	if !mb.IsEmpty() {
		r.activity.mark()
	}
	return mb, err
}

func (r *activityReader) Interrupt()   { common.Interrupt(r.Reader) }
func (r *activityReader) Close() error { return common.Close(r.Reader) }

func (w *activityWriter) Close() error { return common.Close(w.Writer) }
func (w *activityWriter) Interrupt()   { common.Interrupt(w.Writer) }

type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.Counter.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}
