package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/ui"
)

// `pelfs init --grace`, the two things the command owes a user who is
// choosing a number they will live with for the life of the volume:
// refusing one that is unsafe, and saying out loud when one is bigger than
// the ledgers can honour.

func TestInitRefusesAGraceWindowUnderTheFloor(t *testing.T) {
	if _, err := parseGrace("30m"); err == nil {
		t.Fatal("--grace 30m was accepted; under the floor the age guard stops protecting a pack a " +
			"concurrent writer has cut and not yet named, so the volume's own gc can delete live data")
	}
	// The floor itself, and something comfortably above it, are fine.
	for _, s := range []string{"1h", "12h", "720h"} {
		got, err := parseGrace(s)
		if err != nil {
			t.Fatalf("--grace %s was refused: %v", s, err)
		}
		if want, _ := time.ParseDuration(s); got != want {
			t.Fatalf("--grace %s parsed as %v", s, got)
		}
	}
	// Absent means "the default", which the caller signals with zero rather
	// than by knowing what the default is.
	if got, err := parseGrace(""); err != nil || got != 0 {
		t.Fatalf("no --grace gave (%v, %v), want (0, nil)", got, err)
	}
	if publish.MinGrace <= 0 {
		t.Fatal("the floor is not a floor")
	}
}

// The notice is the interaction between a window and the ledger cap,
// delivered at the only moment it is actionable. It has to fire when the
// numbers collide and stay quiet when they do not — a warning on a
// perfectly ordinary volume is a warning users learn to skip.
func TestInitSaysWhenAGraceWindowOutrunsTheLedgers(t *testing.T) {
	capture := func(grace, interval time.Duration) string {
		var buf bytes.Buffer
		restore := ui.SetOutput(&buf, ui.Plain)
		defer restore()
		gracePacingNotice(grace, interval)
		return buf.String()
	}
	loud := capture(30*24*time.Hour, 5*time.Minute)
	if !strings.Contains(loud, "byte cap") {
		t.Fatalf("--grace 30d at a 5m checkpoint interval said nothing about the ledger cap, which binds "+
			"at about 517 rows — roughly 43 hours of that window. Output: %q", loud)
	}
	quiet := capture(8*time.Hour, time.Hour)
	if quiet != "" {
		t.Fatalf("a window the ledgers hold comfortably produced a warning: %q", quiet)
	}
}
