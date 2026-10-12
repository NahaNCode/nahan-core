package limiter

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
	w       io.Writer
	ctx     context.Context
}

func (l *Limiter) RateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
		ctx:     context.Background(),
	}
}

func (l *Limiter) RateWriterContext(writer buf.Writer, bucket *rate.Limiter, ctx context.Context) buf.Writer {
	return &Writer{writer: writer, limiter: bucket, ctx: ctx}
}

func waitBytes(ctx context.Context, bucket *rate.Limiter, n int) error {
	for n > 0 {
		chunk := bucket.Burst()
		if chunk < 1 {
			return io.ErrClosedPipe
		}
		if chunk > n {
			chunk = n
		}
		if err := bucket.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

type Reader struct {
	buf.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

func (l *Limiter) RateReader(reader buf.Reader, bucket *rate.Limiter, ctx context.Context) buf.Reader {
	return &Reader{Reader: reader, limiter: bucket, ctx: ctx}
}
func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if waitErr := waitBytes(r.ctx, r.limiter, int(mb.Len())); waitErr != nil {
		buf.ReleaseMulti(mb)
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
	if err := waitBytes(w.ctx, w.limiter, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *Writer) Interrupt() { common.Interrupt(w.writer) }
