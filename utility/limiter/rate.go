package limiter

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
	w       io.Writer
	ctx     context.Context
	valid   func() bool
}

func (l *Limiter) RateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
		ctx:     context.Background(),
	}
}

func (l *Limiter) RateWriterContext(writer buf.Writer, bucket *rate.Limiter, ctx context.Context, checks ...func() bool) buf.Writer {
	w := &Writer{writer: writer, limiter: bucket, ctx: ctx}
	if len(checks) > 0 {
		w.valid = checks[0]
	}
	return w
}

func waitBytes(ctx context.Context, bucket *rate.Limiter, n int) error {
	return waitBytesChecked(ctx, bucket, n, nil)
}

func waitBytesChecked(ctx context.Context, bucket *rate.Limiter, n int, valid func() bool) error {
	for n > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if valid != nil && !valid() {
			return io.ErrClosedPipe
		}
		chunk := bucket.Burst()
		if chunk < 1 {
			return io.ErrClosedPipe
		}
		if chunk > n {
			chunk = n
		}
		if valid == nil {
			if err := bucket.WaitN(ctx, chunk); err != nil {
				return err
			}
		} else {
			reservation := bucket.ReserveN(time.Now(), chunk)
			if !reservation.OK() {
				return io.ErrClosedPipe
			}
			for delay := reservation.Delay(); delay > 0; delay = reservation.Delay() {
				if delay > time.Second {
					delay = time.Second
				}
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					reservation.Cancel()
					return ctx.Err()
				case <-timer.C:
				}
				if !valid() {
					reservation.Cancel()
					return io.ErrClosedPipe
				}
			}
		}
		n -= chunk
	}
	return nil
}

type Reader struct {
	buf.Reader
	limiter *rate.Limiter
	ctx     context.Context
	valid   func() bool
}

func (l *Limiter) RateReader(reader buf.Reader, bucket *rate.Limiter, ctx context.Context, checks ...func() bool) buf.Reader {
	r := &Reader{Reader: reader, limiter: bucket, ctx: ctx}
	if len(checks) > 0 {
		r.valid = checks[0]
	}
	return r
}
func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if waitErr := waitBytesChecked(r.ctx, r.limiter, int(mb.Len()), r.valid); waitErr != nil {
		buf.ReleaseMulti(mb)
		common.Interrupt(r.Reader)
		return nil, waitErr
	}
	return mb, err
}
func (r *Reader) Interrupt()   { common.Interrupt(r.Reader) }
func (r *Reader) Close() error { return common.Close(r.Reader) }

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := waitBytesChecked(w.ctx, w.limiter, int(mb.Len()), w.valid); err != nil {
		buf.ReleaseMulti(mb)
		common.Interrupt(w.writer)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *Writer) Interrupt() { common.Interrupt(w.writer) }
