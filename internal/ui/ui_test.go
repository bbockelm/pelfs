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
		"pelfs: lease renewal failed (will retry): 503\n"
	if out != want {
		t.Fatalf("plain output:\n%q\nwant:\n%q", out, want)
	}
}

// Every structured line is stamped, levelled, and carries its fields --
// and still carries the prose, so the greps that gate CI keep working
// against a redirected log.
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
	if !strings.HasSuffix(lines[1], "sealed generation 7 (412 chunks) generation=7 chunks=412") {
		t.Errorf("attributes missing or misrendered: %q", lines[1])
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
	if !strings.HasSuffix(structured, "wall=24.031s up=23592960 attempts=1\n") {
		t.Errorf("structured: %q", structured)
	}
}

// Multi-line messages exist so a refusal can explain itself. Every line
// must stay attributable on a terminal; the structured sink keeps one
// record on one line.
func TestMultiLineMessages(t *testing.T) {
	msg := "another client took over this prefix: {holder}\nstop one of them."
	plain := say(t, false, func() { Warn(msg, "holder", "host2") })
	if plain != "pelfs: another client took over this prefix: host2\npelfs: stop one of them.\n" {
		t.Errorf("plain: %q", plain)
	}
	structured := say(t, true, func() { Warn(msg, "holder", "host2") })
	if n := strings.Count(structured, "\n"); n != 1 {
		t.Errorf("structured record spans %d lines: %q", n+1, structured)
	}
	if !strings.Contains(structured, "took over this prefix: host2 stop one of them. holder=host2") {
		t.Errorf("structured: %q", structured)
	}
}

// A brace that names no attribute is left alone rather than eaten: a
// message quoting a shell snippet or a JSON fragment must survive.
func TestUnmatchedPlaceholdersAreLiteral(t *testing.T) {
	out := say(t, false, func() { Info("wrote {\"a\":1} for {who} at {where}", "who", "you") })
	if out != "pelfs: wrote {\"a\":1} for you at {where}\n" {
		t.Fatalf("got %q", out)
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
