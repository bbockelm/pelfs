package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"
)

// say runs fn with output captured in the requested format.
func say(t *testing.T, f Format, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	restore := SetOutput(&buf, f)
	defer restore()
	fn()
	return buf.String()
}

// decode parses a json line into the object a collector would see.
func decode(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSuffix(line, "\n")), &m); err != nil {
		t.Fatalf("json line does not parse (%v): %q", err, line)
	}
	return m
}

// The terminal sink is the one the user reads over the shoulder of a
// running command: prose, prefix, nothing else. A stamp appearing here
// on any line is the regression this package was written to prevent.
func TestPlainIsBareProse(t *testing.T) {
	out := say(t, Plain, func() {
		Info("sealing the overlay into the next generation...")
		Info("sealed generation {generation} ({chunks} chunks)", "generation", 7, "chunks", 412)
		Warn("lease renewal failed (will retry): {error}", "error", errors.New("503"))
	})
	want := "pelfs: sealing the overlay into the next generation...\n" +
		"pelfs: sealed generation 7 (412 chunks)\n" +
		"pelfs: warning: lease renewal failed (will retry): 503\n"
	if out != want {
		t.Fatalf("plain output:\n%q\nwant:\n%q", out, want)
	}
}

// Every text line is stamped and levelled, because whoever opens the file
// was not there when it happened -- and every line is still the sentence,
// because they are a person.
func TestTextStampsEveryLine(t *testing.T) {
	out := say(t, Text, func() {
		Info("sealing the overlay into the next generation...")
		Info("sealed generation {generation} ({chunks} chunks)", "generation", 7, "chunks", 412)
	})
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %q", out)
	}
	stamped := regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[Z+-]\S* INFO pelfs: `)
	for _, l := range lines {
		if !stamped.MatchString(l) {
			t.Errorf("line not stamped: %q", l)
		}
	}
	if !strings.HasSuffix(lines[1], "pelfs: sealed generation 7 (412 chunks)") {
		t.Errorf("values not interpolated, or fields appended: %q", lines[1])
	}
}

// The regression this format exists to fix: a human redirected stderr to a
// file and got "{total} ... total=2.587s" to reassemble in their head.
// Nothing a template names may reach the file as a placeholder, and no
// key=value tail may follow the sentence.
func TestTextLeavesNoPlaceholderUnexpanded(t *testing.T) {
	out := say(t, Text, func() {
		Info("ready to serve in {total} ({packs}; discovery {discovery}, "+
			"lease {lease release}, pack index {index})",
			"total", 2587*time.Millisecond, "packs", Count(9, "pack"),
			"discovery", time.Duration(0), "lease release", 583*time.Millisecond,
			"index", 1019*time.Millisecond)
		Info("uploaded {session} during the session and {teardown} after it exited "+
			"({checkpoints} while mounted, {exitseals} at exit)",
			"session", ByteCount(0), "teardown", ByteCount(4000000),
			"checkpoints", Count(0, "seal"), "exitseals", Count(1, "seal"))
		Warn("lease renewal failed (will retry): {error}", "error", errors.New("503"))
	})
	if strings.ContainsAny(out, "{}") {
		t.Errorf("text output leaked a placeholder:\n%s", out)
	}
	// The tail of fields is what made the prose redundant; it is gone, so
	// no line may end in one.
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if regexp.MustCompile(`\s[a-z_]+=\S+$`).MatchString(l) {
			t.Errorf("text line still carries fields: %q", l)
		}
	}
	if !strings.Contains(out, "ready to serve in 2.6s (9 packs; discovery 0s, "+
		"lease 583ms, pack index 1s)") || !strings.Contains(out, "uploaded 0 B during the session") {
		t.Errorf("prose not rendered as a sentence:\n%s", out)
	}
}

// Each format shows a value ONCE: the two human ones interpolate and emit
// no fields, json emits fields and leaves the placeholders standing. The
// breakdown lines are the case that forced the rule -- their prose is
// nothing but values, so a format doing both doubles the line -- and they
// are the case a well-meaning "but json should read nicely too" would
// regress first.
func TestEachFormatShowsAValueOnce(t *testing.T) {
	emit := func() {
		Info("torn down in {total} (unmount {unmount}, seal {seal})",
			"total", 12907*time.Millisecond, "unmount", 94*time.Millisecond,
			"seal", 12519*time.Millisecond)
	}
	sentence := "pelfs: torn down in 12.9s (unmount 94ms, seal 12.5s)"
	plain := say(t, Plain, emit)
	if plain != sentence+"\n" {
		t.Errorf("plain: %q", plain)
	}
	text := say(t, Text, emit)
	if !strings.HasSuffix(text, sentence+"\n") {
		t.Errorf("text: %q", text)
	}
	for _, out := range []string{plain, text} {
		if strings.ContainsAny(out, "{}") {
			t.Errorf("prose line leaked a placeholder: %q", out)
		}
		if strings.Contains(out, "total=") {
			t.Errorf("prose line leaked a field: %q", out)
		}
	}

	js := say(t, JSON, emit)
	m := decode(t, js)
	if m["msg"] != "torn down in {total} (unmount {unmount}, seal {seal})" {
		t.Errorf("msg is not the template: %q", js)
	}
	if m["total"] != float64(12907*time.Millisecond) {
		t.Errorf("total is not the exact duration: %q", js)
	}
	// Nothing a template named may also appear rendered into its prose.
	for _, dup := range []string{"12.9s", "in 94ms", "seal 12.5s"} {
		if strings.Contains(js, dup) {
			t.Errorf("json record repeats %q: %q", dup, js)
		}
	}
}

// A value carrying a newline must not split the record it belongs to: both
// log formats promise one record per line, and multi-line errors are how
// pelfs refuses things.
func TestLogFormatValuesCannotSplitARecord(t *testing.T) {
	err := errors.New("this prefix holds a retired volume.\nnothing here has been modified")
	for _, f := range []Format{Text, JSON} {
		out := say(t, f, func() { Error("{error}", "error", err) })
		if n := strings.Count(out, "\n"); n != 1 {
			t.Errorf("format %d: record spans %d lines: %q", f, n+1, out)
		}
		// The refusal's words still have to be greppable in the log.
		for _, want := range []string{"retired volume", "nothing here has been modified"} {
			if !strings.Contains(out, want) {
				t.Errorf("format %d: log lost %q: %q", f, want, out)
			}
		}
	}
	if m := decode(t, say(t, JSON, func() { Error("{error}", "error", err) })); m["error"] != err.Error() {
		t.Errorf("json escaped the break away instead of keeping it: %q", m["error"])
	}
}

// Byte counts and counted nouns read as prose and store as numbers; that
// split is the whole reason they are types rather than pre-formatted
// strings.
func TestValuesReadAsProseAndStoreAsNumbers(t *testing.T) {
	emit := func() {
		Info("seal took {wall} ({up} uploaded, {attempts})",
			"wall", 24*time.Second+31*time.Millisecond,
			"up", ByteCount(23592960),
			"attempts", Count(1, "attempt"))
	}
	sentence := "pelfs: seal took 24s (22.5 MiB uploaded, 1 attempt)"
	if plain := say(t, Plain, emit); plain != sentence+"\n" {
		t.Errorf("plain: %q", plain)
	}
	if text := say(t, Text, emit); !strings.HasSuffix(text, sentence+"\n") {
		t.Errorf("text: %q", text)
	}
	m := decode(t, say(t, JSON, emit))
	if m["up"] != float64(23592960) || m["attempts"] != float64(1) ||
		m["wall"] != float64(24031*time.Millisecond) {
		t.Errorf("json stored rounded prose rather than exact values: %v", m)
	}
}

// A share of something reads as a percentage and stores as the fraction: a
// record that kept the "%" would make a collector parse a suffix off every
// one before it could average anything.
func TestPercentReadsAsProseAndStoresAsAFraction(t *testing.T) {
	emit := func() { Info("uploading {uploading} of the seal", "uploading", Percent(0.9375)) }
	if plain := say(t, Plain, emit); plain != "pelfs: uploading 94% of the seal\n" {
		t.Errorf("plain: %q", plain)
	}
	if text := say(t, Text, emit); !strings.HasSuffix(text, "pelfs: uploading 94% of the seal\n") {
		t.Errorf("text: %q", text)
	}
	if m := decode(t, say(t, JSON, emit)); m["uploading"] != 0.9375 {
		t.Errorf("json: %v", m)
	}
}

// Multi-line messages exist so a refusal can explain itself. Every line
// must stay attributable on a terminal; both log formats keep one record
// on one line.
func TestMultiLineMessages(t *testing.T) {
	msg := "another client took over this prefix: {holder}\nstop one of them."
	plain := say(t, Plain, func() { Warn(msg, "holder", "host2") })
	want := "pelfs: warning: another client took over this prefix: host2\n" +
		"pelfs: warning: stop one of them.\n"
	if plain != want {
		t.Errorf("plain:\n%q\nwant:\n%q", plain, want)
	}
	text := say(t, Text, func() { Warn(msg, "holder", "host2") })
	if n := strings.Count(text, "\n"); n != 1 {
		t.Errorf("text record spans %d lines: %q", n+1, text)
	}
	if !strings.HasSuffix(text, "WARN pelfs: another client took over this prefix: host2 stop one of them.\n") {
		t.Errorf("text: %q", text)
	}
	js := say(t, JSON, func() { Warn(msg, "holder", "host2") })
	if n := strings.Count(js, "\n"); n != 1 {
		t.Errorf("json record spans %d lines: %q", n+1, js)
	}
	if m := decode(t, js); m["msg"] != msg || m["level"] != "WARN" {
		t.Errorf("json: %v", m)
	}
}

// A brace that names no attribute is left alone rather than eaten: a
// message quoting a shell snippet or a JSON fragment must survive. That
// holds in all three formats -- json rewrites placeholders, so it has its
// own chance to mangle a fragment that is not one.
func TestUnmatchedPlaceholdersAreLiteral(t *testing.T) {
	emit := func() { Info("wrote {\"a\":1} for {who} at {where}", "who", "you") }
	if out := say(t, Plain, emit); out != "pelfs: wrote {\"a\":1} for you at {where}\n" {
		t.Errorf("plain: %q", out)
	}
	if out := say(t, Text, emit); !strings.HasSuffix(out, "pelfs: wrote {\"a\":1} for you at {where}\n") {
		t.Errorf("text: %q", out)
	}
	if m := decode(t, say(t, JSON, emit)); m["msg"] != "wrote {\"a\":1} for {who} at {where}" {
		t.Errorf("json: %v", m)
	}
}

// Phase clocks name their attributes for the prose ("lease release"), and
// a key with a space in it is one no logfmt reader can express and most
// query languages must quote. The placeholder is normalized with the field
// so that a {name} in msg names a key the record actually carries.
func TestFieldKeysAreLogfmtLegal(t *testing.T) {
	emit := func() {
		Info("torn down in {total} (lease release {lease release})",
			"total", 171*time.Millisecond, "lease release", 77*time.Millisecond)
	}
	sentence := "pelfs: torn down in 171ms (lease release 77ms)"
	if out := say(t, Plain, emit); out != sentence+"\n" {
		t.Errorf("plain: %q", out)
	}
	if out := say(t, Text, emit); !strings.HasSuffix(out, sentence+"\n") {
		t.Errorf("text: %q", out)
	}
	js := say(t, JSON, emit)
	m := decode(t, js)
	if m["msg"] != "torn down in {total} (lease release {lease_release})" {
		t.Errorf("placeholder not normalized with the key: %q", js)
	}
	for k := range m {
		if strings.ContainsAny(k, ` "=`) {
			t.Errorf("key %q is not logfmt-legal: %q", k, js)
		}
	}
	// Every placeholder in msg names a key that is really there.
	for _, ph := range regexp.MustCompile(`\{([^{}]+)\}`).FindAllStringSubmatch(m["msg"].(string), -1) {
		if _, ok := m[ph[1]]; !ok {
			t.Errorf("msg names {%s}, which the record does not carry: %q", ph[1], js)
		}
	}
}

// json is what a collector parses, so every record must parse -- including
// the ones carrying a path with a space, a quote, or a float JSON has no
// literal for.
func TestJSONRecordsAlwaysParse(t *testing.T) {
	out := say(t, JSON, func() {
		Info("mounted", "path", `/tmp/a b/"quoted"`, "backend", "fuse",
			"tabbed", "one\ttwo", "share", Percent(math.NaN()), "ok", true)
	})
	m := decode(t, out)
	if m["path"] != `/tmp/a b/"quoted"` || m["backend"] != "fuse" ||
		m["tabbed"] != "one\ttwo" || m["ok"] != true {
		t.Errorf("values did not survive the round trip: %v", m)
	}
	if m["share"] != "NaN" {
		t.Errorf("a NaN must not be written as a bare JSON literal: %q", out)
	}
}

// The line is assembled in one buffer and written once, so a message costs
// a single Write no matter how many attributes it carries -- which is what
// keeps a record from interleaving with the Pelican client's output or the
// user's own program.
func TestOneWritePerMessage(t *testing.T) {
	for _, f := range []Format{Plain, Text, JSON} {
		var w countingWriter
		restore := SetOutput(&w, f)
		Info("prefetched {chunks} chunks, {bytes}", "chunks", 12, "bytes", ByteCount(1<<20))
		restore()
		if w.n != 1 {
			t.Errorf("format %d: want 1 write, got %d", f, w.n)
		}
	}
}

// Detection chooses only between the two formats written for a person, and
// the machine format is reached by asking. A file is not a collector.
func TestFormatSelection(t *testing.T) {
	for _, c := range []struct {
		env  string
		want Format
	}{
		{"", Text}, // a redirected log file: a human reads it
		{"plain", Plain},
		{"text", Text},
		{"json", JSON},
		{"structured", Text}, // an unrecognized name must not cost a log
	} {
		t.Setenv("PELFS_LOG_FORMAT", c.env)
		if got := FormatFor(new(bytes.Buffer)); got != c.want {
			t.Errorf("PELFS_LOG_FORMAT=%q: got format %d, want %d", c.env, got, c.want)
		}
	}
}

type countingWriter struct{ n int }

func (c *countingWriter) Write(p []byte) (int, error) { c.n++; return len(p), nil }
