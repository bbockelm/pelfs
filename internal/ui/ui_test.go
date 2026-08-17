package ui

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// say runs fn with output captured in the requested format.
func say(t *testing.T, structured bool, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	restore := SetOutput(&buf, structured)
	defer restore()
	fn()
	return buf.String()
}

// The terminal sink is the one the user reads over the shoulder of a
// running command: prose, prefix, nothing else. A stamp appearing here
// on any line is the regression this package was written to prevent.
func TestPlainIsBareProse(t *testing.T) {
	out := say(t, false, func() {
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

// Every structured line is stamped, levelled, and carries its fields --
// and the literal words of its template, so the greps that gate CI keep
// working against a redirected log.
func TestStructuredStampsEveryLine(t *testing.T) {
	out := say(t, true, func() {
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
	if !strings.HasSuffix(lines[1], "sealed generation {generation} ({chunks} chunks) generation=7 chunks=412") {
		t.Errorf("attributes missing or misrendered: %q", lines[1])
	}
}

// Each sink shows a value ONCE: the terminal interpolates and emits no
// fields, the log emits fields and leaves the placeholders standing. The
// breakdown lines are the case that forced the rule -- their prose is
// nothing but values, so a sink doing both doubles the line -- and they
// are the case a well-meaning "but the log should read nicely too" would
// regress first.
func TestEachSinkShowsAValueOnce(t *testing.T) {
	emit := func() {
		Info("torn down in {total} (unmount {unmount}, seal {seal})",
			"total", 12907*time.Millisecond, "unmount", 94*time.Millisecond,
			"seal", 12519*time.Millisecond)
	}
	plain := say(t, false, emit)
	if plain != "pelfs: torn down in 12.9s (unmount 94ms, seal 12.5s)\n" {
		t.Errorf("plain: %q", plain)
	}
	structured := say(t, true, emit)
	if !strings.HasSuffix(structured,
		"pelfs: torn down in {total} (unmount {unmount}, seal {seal}) "+
			"total=12.907s unmount=94ms seal=12.519s\n") {
		t.Errorf("structured: %q", structured)
	}
	// Nothing a template named may also appear rendered into its prose.
	for _, dup := range []string{"12.9s", "in 94ms", "seal 12.5s"} {
		if strings.Contains(structured, dup) {
			t.Errorf("structured line repeats %q: %q", dup, structured)
		}
	}
	if strings.ContainsAny(plain, "{}") {
		t.Errorf("plain line leaked a placeholder: %q", plain)
	}
	if strings.Contains(plain, "total=") {
		t.Errorf("plain line leaked a field: %q", plain)
	}
}

// A value carrying a newline must not split the record it belongs to: the
// structured sink promises one record per line, and multi-line errors are
// how pelfs refuses things.
func TestStructuredValuesCannotSplitARecord(t *testing.T) {
	err := errors.New("this prefix holds a retired volume.\nnothing here has been modified")
	out := say(t, true, func() { Error("{error}", "error", err) })
	if n := strings.Count(out, "\n"); n != 1 {
		t.Errorf("record spans %d lines: %q", n+1, out)
	}
	// The refusal's words still have to be greppable in the log.
	for _, want := range []string{"retired volume", "nothing here has been modified"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lost %q: %q", want, out)
		}
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
	plain := say(t, false, emit)
	if plain != "pelfs: seal took 24s (22.5 MiB uploaded, 1 attempt)\n" {
		t.Errorf("plain: %q", plain)
	}
	structured := say(t, true, emit)
	if !strings.HasSuffix(structured,
		"seal took {wall} ({up} uploaded, {attempts}) wall=24.031s up=23592960 attempts=1\n") {
		t.Errorf("structured: %q", structured)
	}
}

// A share of something reads as a percentage and stores as the fraction:
// a log that kept the "%" would make a collector parse a suffix off every
// record before it could average anything.
func TestPercentReadsAsProseAndStoresAsAFraction(t *testing.T) {
	emit := func() { Info("uploading {uploading} of the seal", "uploading", Percent(0.9375)) }
	if plain := say(t, false, emit); plain != "pelfs: uploading 94% of the seal\n" {
		t.Errorf("plain: %q", plain)
	}
	if structured := say(t, true, emit); !strings.HasSuffix(structured,
		"uploading {uploading} of the seal uploading=0.9375\n") {
		t.Errorf("structured: %q", structured)
	}
}

// Multi-line messages exist so a refusal can explain itself. Every line
// must stay attributable on a terminal; the structured sink keeps one
// record on one line.
func TestMultiLineMessages(t *testing.T) {
	msg := "another client took over this prefix: {holder}\nstop one of them."
	plain := say(t, false, func() { Warn(msg, "holder", "host2") })
	want := "pelfs: warning: another client took over this prefix: host2\n" +
		"pelfs: warning: stop one of them.\n"
	if plain != want {
		t.Errorf("plain:\n%q\nwant:\n%q", plain, want)
	}
	structured := say(t, true, func() { Warn(msg, "holder", "host2") })
	if n := strings.Count(structured, "\n"); n != 1 {
		t.Errorf("structured record spans %d lines: %q", n+1, structured)
	}
	if !strings.Contains(structured, "took over this prefix: {holder} stop one of them. holder=host2") {
		t.Errorf("structured: %q", structured)
	}
}

// A brace that names no attribute is left alone rather than eaten: a
// message quoting a shell snippet or a JSON fragment must survive. That
// holds in both sinks -- the structured one rewrites placeholders, so it
// has its own chance to mangle a fragment that is not one.
func TestUnmatchedPlaceholdersAreLiteral(t *testing.T) {
	emit := func() { Info("wrote {\"a\":1} for {who} at {where}", "who", "you") }
	if out := say(t, false, emit); out != "pelfs: wrote {\"a\":1} for you at {where}\n" {
		t.Errorf("plain: %q", out)
	}
	if out := say(t, true, emit); !strings.HasSuffix(out,
		"wrote {\"a\":1} for {who} at {where} who=you\n") {
		t.Errorf("structured: %q", out)
	}
}

// Phase clocks name their attributes for the prose ("lease release"), and
// logfmt cannot quote a key: unnormalized, "lease release=77ms" parses as
// a valueless key plus a different one. The placeholder is normalized with
// the field so that {name} names a key the line actually carries.
func TestFieldKeysAreLogfmtLegal(t *testing.T) {
	emit := func() {
		Info("torn down in {total} (lease release {lease release})",
			"total", 171*time.Millisecond, "lease release", 77*time.Millisecond)
	}
	if out := say(t, false, emit); out != "pelfs: torn down in 171ms (lease release 77ms)\n" {
		t.Errorf("plain: %q", out)
	}
	out := say(t, true, emit)
	if !strings.HasSuffix(out,
		"torn down in {total} (lease release {lease_release}) total=171ms lease_release=77ms\n") {
		t.Fatalf("structured: %q", out)
	}
	// Every key=value pair on the line must be exactly that.
	for _, f := range strings.Fields(strings.TrimSuffix(out, "\n")) {
		if !strings.Contains(f, "=") {
			continue
		}
		if k, _, _ := strings.Cut(f, "="); strings.ContainsAny(k, ` "=`) {
			t.Errorf("key %q is not logfmt-legal: %q", k, out)
		}
	}
}

func TestStructuredQuotesAmbiguousValues(t *testing.T) {
	out := say(t, true, func() { Info("mounted", "path", "/tmp/a b", "backend", "fuse") })
	if !strings.HasSuffix(out, `path="/tmp/a b" backend=fuse`+"\n") {
		t.Fatalf("got %q", out)
	}
}

// The line is assembled in one buffer and written once, so a message
// costs a single Write no matter how many attributes it carries.
func TestOneWritePerMessage(t *testing.T) {
	var w countingWriter
	restore := SetOutput(&w, true)
	defer restore()
	Info("prefetched {chunks} chunks, {bytes}", "chunks", 12, "bytes", ByteCount(1<<20))
	if w.n != 1 {
		t.Fatalf("want 1 write, got %d", w.n)
	}
}

type countingWriter struct{ n int }

func (c *countingWriter) Write(p []byte) (int, error) { c.n++; return len(p), nil }
