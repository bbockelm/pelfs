// Package ui is pelfs's voice. Every line the program says to its user
// goes through here, so "what does a pelfs message look like" is answered
// in one place rather than at a hundred call sites — which is how the
// output came to carry three different formats, one of them applied to
// exactly two lines.
//
// # Timestamps are a property of the sink, not of the message
//
// On an interactive terminal a line is printed bare, save for the level
// when it is not routine:
//
//	pelfs: sealing the overlay into the next generation...
//	pelfs: warning: another client took over this prefix
//
// The reader is watching it happen; their terminal already knows the
// time, and a stamp on every conversational line is noise. When stderr is
// NOT a terminal — a detached `pelfs mount` writing to its log file, CI,
// a log collector — every line carries a timestamp, a level, and its
// structured attributes, because nobody was there when it happened and
// the file is what gets grepped afterwards.
//
// There is deliberately no per-message exception and no --log-timestamps
// flag. Both would put the decision back at the call site, and a rule
// that stamps only the "important" lines produces exactly the output that
// made this package necessary: one stamped line in a run of unstamped
// ones reads as a bug, not as emphasis. The case the exception was
// reaching for — a user waiting out a long seal or upload — is served
// better by having those messages report their own DURATION ("seal took
// 24s"), which answers "how long did that take" that a pair of wall-clock
// stamps only implies; and the case where "when" genuinely cannot be
// recovered, an unattended mount, is precisely the non-terminal sink
// where everything is stamped.
//
// PELFS_LOG_FORMAT=plain|structured overrides the detection. That is not
// a second policy — it is for the two places detection is wrong: a
// container with a pseudo-tty whose output is really going to a CI log,
// and a human piping prose into a pager.
//
// # The pelfs: prefix stays, in both modes
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
// The plain sink renders the sentence:
//
//	pelfs: sealed generation 7 (412 chunks)
//
// The structured sink renders the TEMPLATE and the fields:
//
//	…INFO pelfs: sealed generation {generation} ({chunks} chunks) generation=7 chunks=412
//
// Values live in exactly one place at the call site, the prose stays a
// sentence written for a human, and the machine-readable view comes for
// free. Attributes carry the values worth extracting — generations, keys,
// durations, byte counts; a message with nothing to extract simply passes
// no attributes.
//
// The structured sink does NOT also render the sentence. Every value pelfs
// logs is named by its template — so a sink that interpolated as well as
// emitted fields printed all of them twice on one line, and the two
// breakdowns that are nothing but values ("torn down in …", "ready to
// serve in …") came out at double length with the prose buried in front of
// its own duplicate. Which of the two views to show is the sink's decision
// to make, and each sink now makes it once, for its own reader: a person
// watching gets the sentence, a log gets the fields it can do arithmetic
// on plus a message that is CONSTANT — groupable, countable across runs,
// and immune to a value that happens to contain a newline. An attribute
// named for the prose that reads it back ("lease release") becomes a
// logfmt-legal key, in the placeholder as well as in the field, so {name}
// always names a key that is really there.
//
// Greps against a log are unaffected by that choice and must stay that
// way: it is the literal words of a template that scripts match, so a
// message must carry the words its readers look for OUTSIDE its
// placeholders.
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

func init() { current.Store(newLogger(os.Stderr, structuredFor(os.Stderr))) }

// Info states what pelfs is doing. Most of what pelfs says is this:
// progress a user asked for by running the command.
func Info(msg string, args ...any) { current.Load().Info(msg, args...) }

// Warn reports something the user should know about but that did not
// stop the operation.
func Warn(msg string, args ...any) { current.Load().Warn(msg, args...) }

// Error reports a failure. It does not exit; the caller owns the exit
// status.
func Error(msg string, args ...any) { current.Load().Error(msg, args...) }

// structuredFor reports whether w should get timestamped, attributed
// output rather than bare prose. A background mount needs no special
// case: its stderr IS the log file it was spawned with, so it answers
// this question about the file and formats accordingly.
func structuredFor(w io.Writer) bool {
	switch os.Getenv("PELFS_LOG_FORMAT") {
	case "plain":
		return false
	case "structured":
		return true
	}
	f, ok := w.(*os.File)
	if !ok {
		return true
	}
	return !term.IsTerminal(int(f.Fd()))
}

// SetOutput redirects every pelfs message to w in the given format and
// returns a function restoring the previous destination. For tests.
func SetOutput(w io.Writer, structured bool) func() {
	prev := current.Swap(newLogger(w, structured))
	return func() { current.Store(prev) }
}

func newLogger(w io.Writer, structured bool) *slog.Logger {
	return slog.New(&handler{w: w, mu: new(sync.Mutex), structured: structured})
}

// handler renders records in pelfs's two formats. It is the only place
// either format is decided.
type handler struct {
	w          io.Writer
	mu         *sync.Mutex
	structured bool
	// with holds attributes bound by WithAttrs, which apply to every
	// record this handler emits.
	with []slog.Attr
}

// Enabled: pelfs has no debug channel. Everything it says is addressed
// to the user running it, and anything below Info would be addressed to
// us instead.
func (h *handler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

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
