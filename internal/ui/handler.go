package ui

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// prefix identifies our lines on a terminal three programs are writing
// to. See the package comment.
const prefix = "pelfs: "

// timeLayout is RFC3339 with milliseconds and a zone offset: sortable,
// unambiguous across a daylight-saving boundary, and what every log
// collector already parses.
const timeLayout = "2006-01-02T15:04:05.000Z07:00"

// bufs recycles line buffers. Messages are emitted one line at a time
// under a lock, so a pool of a few buffers serves every goroutine.
var bufs = sync.Pool{New: func() any { b := make([]byte, 0, 256); return &b }}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	// A fixed array covers every message pelfs sends; nothing here
	// carries more attributes than this.
	var stack [12]slog.Attr
	attrs := append(stack[:0], h.with...)
	r.Attrs(func(a slog.Attr) bool { attrs = append(attrs, a); return true })

	bp := bufs.Get().(*[]byte)
	b := (*bp)[:0]
	if h.structured {
		b = r.Time.AppendFormat(b, timeLayout)
		b = append(b, ' ')
		b = append(b, levelName(r.Level)...)
		b = append(b, ' ')
	}
	b = append(b, prefix...)
	b = expand(b, r.Message, attrs, h.structured)
	if h.structured {
		for _, a := range attrs {
			b = append(b, ' ')
			b = appendField(b, a)
		}
	}
	b = append(b, '\n')

	// One Write per line, under a lock: stderr is shared with the
	// Pelican client and, in `pelfs shell`, with the user's own program.
	// A half-written line interleaved with theirs is unreadable.
	h.mu.Lock()
	_, err := h.w.Write(b)
	h.mu.Unlock()

	*bp = b
	bufs.Put(bp)
	return err
}

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARN"
	default:
		return "INFO"
	}
}

// expand writes msg, substituting {name} with the value of the attribute
// of that name. A brace run that names no attribute is left alone, so a
// message containing literal braces is harmless rather than mangled.
//
// A newline in a message starts a continuation line, which is re-prefixed
// so that every line on the terminal is attributable. The structured sink
// keeps one record on one line and joins the continuations with a space.
func expand(b []byte, msg string, attrs []slog.Attr, structured bool) []byte {
	for len(msg) > 0 {
		i := strings.IndexAny(msg, "{\n")
		if i < 0 {
			return append(b, msg...)
		}
		b = append(b, msg[:i]...)
		if msg[i] == '\n' {
			if structured {
				b = append(b, ' ')
			} else {
				b = append(b, '\n')
				b = append(b, prefix...)
			}
			msg = msg[i+1:]
			continue
		}
		rest := msg[i+1:]
		j := strings.IndexByte(rest, '}')
		if j < 0 {
			return append(b, msg[i:]...)
		}
		name := rest[:j]
		if v, ok := lookup(attrs, name); ok {
			b = appendValue(b, v)
		} else {
			b = append(b, msg[i:i+j+2]...)
		}
		msg = rest[j+1:]
	}
	return b
}

func lookup(attrs []slog.Attr, name string) (slog.Value, bool) {
	for _, a := range attrs {
		if a.Key == name {
			return a.Value, true
		}
	}
	return slog.Value{}, false
}

// appendValue renders a value as prose, the way the sentence around it
// needs to read.
func appendValue(b []byte, v slog.Value) []byte {
	switch v.Kind() {
	case slog.KindString:
		return append(b, v.String()...)
	case slog.KindInt64:
		return strconv.AppendInt(b, v.Int64(), 10)
	case slog.KindUint64:
		return strconv.AppendUint(b, v.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.AppendFloat(b, v.Float64(), 'f', -1, 64)
	case slog.KindBool:
		return strconv.AppendBool(b, v.Bool())
	case slog.KindDuration:
		return append(b, humanDuration(v.Duration())...)
	case slog.KindTime:
		return v.Time().AppendFormat(b, timeLayout)
	}
	switch a := v.Any().(type) {
	case error:
		return append(b, a.Error()...)
	case fmt.Stringer:
		return append(b, a.String()...)
	default:
		return fmt.Appendf(b, "%v", a)
	}
}

// appendField renders one attribute in logfmt, which is what the
// non-terminal sink exists to produce. Byte counts and attempt counts go
// out as bare numbers here even though the sentence humanized them: the
// prose is for reading, the field is for arithmetic.
func appendField(b []byte, a slog.Attr) []byte {
	b = append(b, a.Key...)
	b = append(b, '=')
	switch v := a.Value.Any().(type) {
	case ByteCount:
		return strconv.AppendInt(b, int64(v), 10)
	case Plural:
		return strconv.AppendInt(b, v.N, 10)
	}
	switch a.Value.Kind() {
	case slog.KindInt64:
		return strconv.AppendInt(b, a.Value.Int64(), 10)
	case slog.KindUint64:
		return strconv.AppendUint(b, a.Value.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.AppendFloat(b, a.Value.Float64(), 'f', -1, 64)
	case slog.KindBool:
		return strconv.AppendBool(b, a.Value.Bool())
	case slog.KindDuration:
		return appendQuoted(b, a.Value.Duration().String())
	}
	var s string
	switch v := a.Value.Any().(type) {
	case error:
		s = v.Error()
	case fmt.Stringer:
		s = v.String()
	case string:
		s = v
	default:
		s = fmt.Sprintf("%v", v)
	}
	return appendQuoted(b, s)
}

// appendQuoted quotes only when the value would otherwise be ambiguous
// to a logfmt reader, so the common case stays readable to a human.
func appendQuoted(b []byte, s string) []byte {
	if s == "" || strings.ContainsAny(s, ` "=\`) {
		return strconv.AppendQuote(b, s)
	}
	return append(b, s...)
}

// humanDuration keeps a duration to the precision a reader can act on:
// milliseconds for something that felt instant, tenths for something they
// noticed, whole seconds for something they waited out. Full precision
// survives in the structured field.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	default:
		return d.Round(time.Second).String()
	}
}

// ByteCount is a size that reads as a size in prose ("22.5 MiB") and
// stays a number in the structured field.
type ByteCount int64

func (n ByteCount) String() string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// Plural is a count with its noun. "(s)" in an operator-facing message is
// a refusal to decide; the structured field keeps the bare number.
type Plural struct {
	N    int64
	Noun string
}

// Count pairs a number with the thing it counts.
func Count[T ~int | ~int64](n T, noun string) Plural { return Plural{N: int64(n), Noun: noun} }

func (p Plural) String() string {
	if p.N == 1 {
		return "1 " + p.Noun
	}
	return strconv.FormatInt(p.N, 10) + " " + p.Noun + "s"
}
