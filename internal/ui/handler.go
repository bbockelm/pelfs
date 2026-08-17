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
// to. See the package comment. A warning or an error says so in the
// prose lead as well, so that the level a collector reads as a field is
// the same level a person reads on the terminal -- and so that call
// sites stop shouting WARNING at each other in the message text.
const (
	prefix     = "pelfs: "
	warnPrefix = "pelfs: warning: "
	errPrefix  = "pelfs: error: "
)

func linePrefix(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return errPrefix
	case l >= slog.LevelWarn:
		return warnPrefix
	default:
		return prefix
	}
}

// timeLayout is RFC3339 with milliseconds and a zone offset: sortable,
// unambiguous across a daylight-saving boundary, and what every log
// collector already parses.
const timeLayout = "2006-01-02T15:04:05.000Z07:00"

// bufs recycles line buffers. Messages are emitted one line at a time
// under a lock, so a pool of a few buffers serves every goroutine.
var bufs = sync.Pool{New: func() any { b := make([]byte, 0, 256); return &b }}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	// A fixed array holds the attributes of every message pelfs actually
	// sends; a longer one still works, it just allocates.
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
	// The structured header already carries the level, so only the
	// terminal line needs it spelled out.
	lead := prefix
	if !h.structured {
		lead = linePrefix(r.Level)
	}
	b = append(b, lead...)
	if h.structured {
		b = flatten(b, r.Message, attrs)
		for _, a := range attrs {
			b = append(b, ' ')
			b = appendField(b, a)
		}
	} else {
		b = expand(b, lead, r.Message, attrs)
	}
	b = append(b, '\n')

	// One Write per line, under a lock: stderr is shared with the
	// Pelican client and, in `pelfs shell`, with the user's own program.
	// A half-written line interleaved with theirs is unreadable.
	h.mu.Lock()
	_, err := h.w.Write(b)
	h.mu.Unlock()

	// A buffer that grew to hold one enormous message must not be kept
	// alive by the pool for the life of the process.
	if cap(b) <= 8<<10 {
		*bp = b
		bufs.Put(bp)
	}
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

// flatten writes msg for the structured sink: one record on one line,
// with its {name} placeholders left standing rather than substituted.
//
// Substituting here as well as emitting the fields printed every value
// twice on the same line, which on the phase breakdowns -- sentences that
// are nothing but values -- doubled the line and buried the content. The
// template is also worth more to a reader of a log than the rendered
// sentence is: it is constant, so a collector can group by it and count
// occurrences across runs, and {name} says exactly which field below
// carries the value. Grepping is unaffected, because the literal words
// of a template are what greps match, and a value can no longer smuggle a
// newline into the middle of a record.
func flatten(b []byte, msg string, attrs []slog.Attr) []byte {
	for len(msg) > 0 {
		i := strings.IndexAny(msg, "{\n")
		if i < 0 {
			return append(b, msg...)
		}
		b = append(b, msg[:i]...)
		if msg[i] == '\n' {
			b = append(b, ' ')
			msg = msg[i+1:]
			continue
		}
		rest := msg[i+1:]
		j := strings.IndexByte(rest, '}')
		if j < 0 {
			return append(b, msg[i:]...)
		}
		// A placeholder naming no attribute is left exactly as written,
		// for the same reason expand leaves it: the message is quoting a
		// shell snippet or a JSON fragment, not naming a field.
		if _, ok := lookup(attrs, rest[:j]); ok {
			b = append(b, '{')
			b = appendFieldKey(b, rest[:j])
			b = append(b, '}')
		} else {
			b = append(b, msg[i:i+j+2]...)
		}
		msg = rest[j+1:]
	}
	return b
}

// expand writes msg for the terminal, substituting {name} with the value
// of the attribute of that name. A brace run that names no attribute is
// left alone, so a message containing literal braces is harmless rather
// than mangled.
//
// A newline in a message starts a continuation line, which is re-prefixed
// with lead so that every line on the terminal is attributable and a
// warning does not lose its warning after the first line.
func expand(b []byte, lead, msg string, attrs []slog.Attr) []byte {
	for len(msg) > 0 {
		i := strings.IndexAny(msg, "{\n")
		if i < 0 {
			return append(b, msg...)
		}
		b = append(b, msg[:i]...)
		if msg[i] == '\n' {
			b = append(b, '\n')
			b = append(b, lead...)
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
	b = appendFieldKey(b, a.Key)
	b = append(b, '=')
	switch v := a.Value.Any().(type) {
	case ByteCount:
		return strconv.AppendInt(b, int64(v), 10)
	case Plural:
		return strconv.AppendInt(b, v.N, 10)
	case Percent:
		return strconv.AppendFloat(b, float64(v), 'f', -1, 64)
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

// appendFieldKey renders an attribute name as a logfmt key. A phase clock
// names its attributes for the prose that reads them back ("lease
// release", "pack index"), and logfmt has no way to quote a key, so a
// space in one silently splits it into two keys -- and the fields are now
// the whole of what a collector gets. The call site keeps writing the
// label a person reads; the sink makes it parseable, which is where every
// other formatting decision in this package lives too.
func appendFieldKey(b []byte, name string) []byte {
	for i := 0; i < len(name); i++ {
		if c := name[i]; c == ' ' || c == '=' || c == '"' {
			b = append(b, '_')
		} else {
			b = append(b, c)
		}
	}
	return b
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

// Percent is a fraction in [0,1] that reads as a percentage in prose
// ("94%") and stays the fraction in the structured field, where a
// collector can average it across runs without parsing a suffix.
type Percent float64

func (p Percent) String() string { return fmt.Sprintf("%.0f%%", float64(p)*100) }

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
