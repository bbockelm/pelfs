package ui

import (
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// appendJSON renders one record as a single JSON object, the format a
// collector gets when it asks for one.
//
// msg is the message TEMPLATE, not the rendered sentence: it is constant
// across runs, so records can be grouped and counted by it, and each
// {name} in it says which field carries that value -- which is also why
// the values are not interpolated as well. The fields hold the exact
// value, not the rounded prose the sentence reads: a size is a count of
// bytes, a share is a fraction, a duration is a count of nanoseconds. That
// is slog's own JSON convention, and it spares every consumer the job of
// parsing a unit off a string before it can do arithmetic.
func appendJSON(b []byte, r slog.Record, attrs []slog.Attr) []byte {
	b = append(b, `{"time":"`...)
	b = r.Time.AppendFormat(b, timeLayout)
	b = append(b, `","level":"`...)
	b = append(b, levelName(r.Level)...)
	b = append(b, `","msg":`...)
	b = appendJSONTemplate(b, r.Message, attrs)
	for _, a := range attrs {
		b = append(b, ',', '"')
		b = appendFieldKey(b, a.Key)
		b = append(b, '"', ':')
		b = appendJSONValue(b, a.Value)
	}
	return append(b, '}')
}

// appendJSONTemplate writes msg as a JSON string with its {name}
// placeholders normalized to the keys the object really carries. A
// placeholder naming no attribute is left exactly as written, for the same
// reason expand leaves it: the message is quoting a shell snippet or a
// JSON fragment, not naming a field.
func appendJSONTemplate(b []byte, msg string, attrs []slog.Attr) []byte {
	b = append(b, '"')
	for len(msg) > 0 {
		i := strings.IndexByte(msg, '{')
		if i < 0 {
			b = appendJSONBody(b, msg)
			break
		}
		b = appendJSONBody(b, msg[:i])
		rest := msg[i+1:]
		j := strings.IndexByte(rest, '}')
		if j < 0 {
			b = appendJSONBody(b, msg[i:])
			break
		}
		if _, ok := lookup(attrs, rest[:j]); ok {
			b = append(b, '{')
			b = appendFieldKey(b, rest[:j])
			b = append(b, '}')
		} else {
			b = appendJSONBody(b, msg[i:i+j+2])
		}
		msg = rest[j+1:]
	}
	return append(b, '"')
}

func appendJSONValue(b []byte, v slog.Value) []byte {
	switch a := v.Any().(type) {
	case ByteCount:
		return strconv.AppendInt(b, int64(a), 10)
	case Plural:
		return strconv.AppendInt(b, a.N, 10)
	case Percent:
		return appendJSONFloat(b, float64(a))
	}
	switch v.Kind() {
	case slog.KindInt64:
		return strconv.AppendInt(b, v.Int64(), 10)
	case slog.KindUint64:
		return strconv.AppendUint(b, v.Uint64(), 10)
	case slog.KindFloat64:
		return appendJSONFloat(b, v.Float64())
	case slog.KindBool:
		return strconv.AppendBool(b, v.Bool())
	case slog.KindDuration:
		return strconv.AppendInt(b, int64(v.Duration()), 10)
	case slog.KindTime:
		b = append(b, '"')
		b = v.Time().AppendFormat(b, timeLayout)
		return append(b, '"')
	}
	var s string
	switch a := v.Any().(type) {
	case error:
		s = a.Error()
	case fmt.Stringer:
		s = a.String()
	case string:
		s = a
	default:
		s = fmt.Sprintf("%v", a)
	}
	return appendJSONString(b, s)
}

// appendJSONFloat falls back to a string for the values JSON has no
// literal for, so one NaN cannot make a record unparseable.
func appendJSONFloat(b []byte, f float64) []byte {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return appendJSONString(b, strconv.FormatFloat(f, 'g', -1, 64))
	}
	return strconv.AppendFloat(b, f, 'g', -1, 64)
}

func appendJSONString(b []byte, s string) []byte {
	b = append(b, '"')
	b = appendJSONBody(b, s)
	return append(b, '"')
}

const hexdigits = "0123456789abcdef"

// appendJSONBody escapes s into the body of a JSON string. Control
// characters -- a newline in a multi-line refusal, above all -- become
// escapes rather than breaks, which is what keeps one record on one line.
// Bytes that are not valid UTF-8 become U+FFFD: pelfs logs paths, and a
// path is a byte string that need not be text.
func appendJSONBody(b []byte, s string) []byte {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			switch c {
			case '"':
				b = append(b, '\\', '"')
			case '\\':
				b = append(b, '\\', '\\')
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				if c < 0x20 {
					b = append(b, '\\', 'u', '0', '0', hexdigits[c>>4], hexdigits[c&0xf])
				} else {
					b = append(b, c)
				}
			}
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			b = utf8.AppendRune(b, utf8.RuneError)
			i++
			continue
		}
		b = append(b, s[i:i+n]...)
		i += n
	}
	return b
}
