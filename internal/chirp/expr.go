package chirp

import "strconv"

// Expr is a ClassAd EXPRESSION, already in the syntax the schedd will
// parse. It is a distinct type and not a string so that a caller cannot
// hand a bare Go string to SetJobAttr by accident: an unquoted string
// value is not a harmless mistake, it is an expression the job ad
// evaluates, and `set_job_attr X Foo || True` is an injection into
// somebody's job. Every value therefore has to be built by one of the
// constructors below, and the only one that emits its argument verbatim
// is named Raw.
type Expr string

// Int renders an integer literal.
func Int[T ~int | ~int32 | ~int64](v T) Expr {
	return Expr(strconv.FormatInt(int64(v), 10))
}

// Uint renders an unsigned integer literal. ClassAd integers are signed
// 64-bit, so a value past MaxInt64 would parse as something else; it is
// clamped rather than wrapped, because the attributes this package
// publishes are counters and a saturated counter is readable while a
// negative one is a bug report.
func Uint[T ~uint | ~uint32 | ~uint64](v T) Expr {
	if uint64(v) > 1<<63-1 {
		return Expr(strconv.FormatInt(1<<63-1, 10))
	}
	return Expr(strconv.FormatUint(uint64(v), 10))
}

// Bool renders a ClassAd boolean literal.
func Bool(b bool) Expr {
	if b {
		return "true"
	}
	return "false"
}

// Raw is the escape hatch: v is used verbatim as an expression. Nothing
// in this package's reporting path calls it, and a caller that does is
// asserting that v came from the program and not from a filename, an
// error string, or anything else a payload can influence.
func Raw(v string) Expr { return Expr(v) }

// String renders s as a ClassAd string LITERAL, quotes included.
//
// This is the injection boundary. The value reaching here is routinely
// an error message, which means it can carry a path a user chose, and a
// value that is not quoted -- or that is quoted but still contains a
// bare `"` or a newline -- either parses as a different expression or
// fails to parse at all. Both outcomes are worse than the message.
//
// The escapes are the ones the ClassAd lexer defines: the named ones for
// the whitespace and quoting characters, and a THREE-digit octal escape
// for every other control byte. Three digits and not fewer because the
// lexer consumes up to three, so `\1` followed by the digit `2` would be
// read as `\12`; `\001` cannot be extended by anything that follows it.
//
// Bytes >= 0x80 pass through unchanged: a ClassAd string is a byte
// string, and mangling UTF-8 here would make non-ASCII filenames
// unreadable in the very message meant to identify them.
func String(s string) Expr {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b = append(b, '\\', '\\')
		case '"':
			b = append(b, '\\', '"')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		case '\a':
			b = append(b, '\\', 'a')
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\v':
			b = append(b, '\\', 'v')
		default:
			if c < 0x20 || c == 0x7f {
				b = append(b, '\\', '0'+(c>>6&7), '0'+(c>>3&7), '0'+(c&7))
				continue
			}
			b = append(b, c)
		}
	}
	b = append(b, '"')
	return Expr(b)
}

// validName reports whether name is a ClassAd identifier. The wire form
// gives an attribute name a whole word of its own, so a name with a
// space in it would silently shift the value into the name's position;
// and a name that is not an identifier cannot be referenced from a
// periodic_hold expression, which is the entire point of setting it.
func validName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
