// Package ui is pelfs's voice. Every line the program says to its user
// goes through here, so "what does a pelfs message look like" is answered
// in one place rather than at a hundred call sites — where the answer
// drifts every few messages and the output carries a different shape in
// each corner of the program.
//
// # Format is a property of the sink; the reader is a human either way
//
// There are three formats, and detection chooses between the two written
// for a person:
//
//	plain  pelfs: sealed generation 7 (412 chunks)
//	text   2026-08-17T15:51:29.584-05:00 INFO pelfs: sealed generation 7 (412 chunks)
//	json   {"time":"…","level":"INFO","msg":"sealed generation {generation} ({chunks} chunks)","generation":7,"chunks":412}
//
// plain is the default on a terminal. The reader is watching it happen;
// their terminal already knows the time, and a stamp on every
// conversational line is noise.
//
// text is the default when stderr is NOT a terminal, because the
// overwhelmingly common non-terminal reader is still a person: someone
// who ran `pelfs mount 2>>pelfs.log` and will open that file later. What
// they lost by not being present is WHEN, so every line is stamped and
// levelled; what they did not lose is the ability to read English, so the
// sentence is rendered in full and nothing is appended after it. Inferring
// "a machine is reading this" from the absence of a tty gets that reader
// wrong: it makes the common case read a template ("ready to serve in
// {total} … total=2.587s") that a person has to reassemble in their head,
// which is worse for them than either the prose or the fields alone.
//
// json is the machine format, and it is reached only by asking for it.
// It is where the properties a collector needs live: msg is the message
// TEMPLATE, so it is constant across runs and can be grouped and counted;
// the attributes are typed JSON values, so a size is the number of bytes
// rather than "22.5 MiB"; and no value is written twice.
//
// PELFS_LOG_FORMAT=plain|text|json overrides the detection, which is how a
// collector asks for json, and also covers the two places detection is
// wrong: a container with a pseudo-tty whose output is really going to a
// CI log, and a human piping prose into a pager.
//
// There is deliberately no per-message exception and no --log-timestamps
// flag. Both would put the decision back at the call site, and a rule
// that stamps only the "important" lines produces exactly the output this
// package exists to prevent: one stamped line in a run of unstamped ones
// reads as a bug, not as emphasis. The case such an exception reaches
// for — a user waiting out a long seal or upload — is served better by
// having those messages report their own DURATION ("seal took 24s"),
// which answers "how long did that take" that a pair of wall-clock stamps
// only implies.
//
// # The pelfs: prefix stays, in every format
//
// Three writers share one terminal during `pelfs shell`: pelfs, the
// Pelican client (logging through logrus, configured by
// PELICAN_LOGGING_LEVEL), and the user's own program. Ours is the only
// one of the three the user can hold responsible, so it must be
// identifiable at a glance and by a fixed grep. We deliberately do NOT
// harmonize with the Pelican client's format: making our lines look like
// the library's would erase the one distinction the reader needs.
//
// # Message templates
//
// A message may interpolate its own attributes by name:
//
//	ui.Info("sealed generation {generation} ({chunks} chunks)",
//	    "generation", gen, "chunks", n)
//
// Values live in exactly one place at the call site, the prose stays a
// sentence written for a human, and the machine-readable view comes for
// free. Attributes carry the values worth extracting — generations, keys,
// durations, byte counts; a message with nothing to extract simply passes
// no attributes.
//
// No format shows a value twice. Every value pelfs logs is named by its
// template, so a sink that interpolated AND emitted fields would print all
// of them twice on one line, and the breakdowns that are nothing but
// values ("torn down in …", "ready to serve in …") would come out at
// double length with the prose buried in front of its own duplicate. Each
// sink picks one view for its own reader: plain and text render the
// sentence and stop, json emits the template and the fields. A value that
// happens to contain a newline cannot split a record in either of the two
// log formats — text folds it, json escapes it.
//
// An attribute named for the prose that reads it back ("lease release")
// becomes a key with no space in it, in the placeholder as well as in the
// field, so a json {name} always names a key that is really there and no
// query language has to quote it.
//
// Greps against a log are unaffected by the choice of format and must stay
// that way: it is the literal words of a template that scripts match, so a
// message must carry the words its readers look for OUTSIDE its
// placeholders.
//
// # One channel is addressed to us instead
//
// Everything above is written for the user. Debug is the exception: it is
// the internal detail that answers "why did that take four minutes" once
// a report arrives, and it is silent unless --debug asks for it. It is a
// channel, not a volume knob — a line belongs there when a maintainer
// would ask for it and a user never would, not when the author was unsure
// whether a message was worth printing. Everything else about it is
// unchanged: it is a sentence, it carries its values as attributes, and
// it wears the same prefix, because the reader who turned it on is
// reading it in the same terminal as the rest.
package ui

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/term"
)

// current is the process-wide logger. Swapped by SetOutput in tests;
// read on every message, so it is an atomic pointer rather than a
// mutex-guarded variable.
var current atomic.Pointer[slog.Logger]

// level is the lowest level any sink emits: Info, or Debug once --debug
// says so. It lives beside the logger rather than inside a handler
// because SetOutput builds a new handler, and a test (or a redirect)
// must not silently undo the channel the user asked for.
var level atomic.Int64

func init() {
	current.Store(newLogger(os.Stderr, FormatFor(os.Stderr)))
	level.Store(int64(slog.LevelInfo))
}

// Format is how a sink renders a record. See the package comment for what
// each one is for and who reads it.
type Format int

const (
	// Plain is bare prose for someone watching a command run.
	Plain Format = iota
	// Text is stamped, levelled prose for someone reading a log file.
	Text
	// JSON is one object per line for a collector.
	JSON
)

// Info states what pelfs is doing. Most of what pelfs says is this:
// progress a user asked for by running the command.
func Info(msg string, args ...any) { current.Load().Info(msg, args...) }

// Warn reports something the user should know about but that did not
// stop the operation.
func Warn(msg string, args ...any) { current.Load().Warn(msg, args...) }

// Error reports a failure. It does not exit; the caller owns the exit
// status.
func Error(msg string, args ...any) { current.Load().Error(msg, args...) }

// Debug is addressed to whoever maintains pelfs rather than to whoever
// runs it: what the program did internally, for the run someone is trying
// to explain. It is silent unless SetDebug turns it on.
func Debug(msg string, args ...any) { current.Load().Debug(msg, args...) }

// SetDebug opens or closes the debug channel for the whole process. It is
// what --debug is wired to, and it is process-wide because the question
// --debug asks ("what is this run doing") is not one any single package
// can answer alone.
func SetDebug(on bool) {
	if on {
		level.Store(int64(slog.LevelDebug))
		return
	}
	level.Store(int64(slog.LevelInfo))
}

// FormatFor picks the format for w: whatever PELFS_LOG_FORMAT names, else
// Plain for a terminal and Text for anything else. Only a human's two
// formats are ever inferred — a machine reading this output says so, by
// asking for json, because "not a terminal" describes a redirected log
// file far more often than it describes a collector. A background mount
// needs no special case: its stderr IS the log file it was spawned with,
// so it answers this question about the file and formats accordingly.
//
// An unrecognized value falls back to detection rather than failing — a
// typo must not cost a user their log — but it SAYS so. Falling back
// silently is worse than either: someone who asked for timestamps and got
// the terminal format reads the absence as a regression in the program
// rather than a typo in their shell, which is exactly what happened.
func FormatFor(w io.Writer) Format {
	switch v := os.Getenv("PELFS_LOG_FORMAT"); v {
	case "plain":
		return Plain
	case "text":
		return Text
	case "json":
		return JSON
	case "":
	default:
		Warn("PELFS_LOG_FORMAT={value} is not one of plain, text or json; "+
			"choosing by whether this is a terminal instead", "value", v)
	}
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return Plain
	}
	return Text
}

// SetOutput redirects every pelfs message to w in the given format and
// returns a function restoring the previous destination. For tests.
func SetOutput(w io.Writer, f Format) func() {
	prev := current.Swap(newLogger(w, f))
	return func() { current.Store(prev) }
}

func newLogger(w io.Writer, f Format) *slog.Logger {
	return slog.New(&handler{w: w, mu: new(sync.Mutex), format: f})
}

// handler renders records in pelfs's three formats. It is the only place
// any of them is decided.
type handler struct {
	w      io.Writer
	mu     *sync.Mutex
	format Format
	// with holds attributes bound by WithAttrs, which apply to every
	// record this handler emits.
	with []slog.Attr
}

// Enabled gates the one channel that is not addressed to the user.
// Everything at Info and above is; Debug is addressed to us, and stays
// off until --debug (SetDebug) asks for it.
func (h *handler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= slog.Level(level.Load())
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	c := *h
	c.with = append(append(make([]slog.Attr, 0, len(h.with)+len(attrs)), h.with...), attrs...)
	return &c
}

// WithGroup is a no-op: pelfs messages are flat, and a group would
// namespace the very attribute names the templates interpolate by.
func (h *handler) WithGroup(string) slog.Handler { return h }
