package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/ui"
)

// --debug used to reach exactly one place: the FUSE library's protocol
// tracing. On the NFS backend, and on every command that mounts nothing
// at all, asking for verbose logging changed not one line of output.
// It now opens the ui debug channel as well, and still carries the FUSE
// flag for the backend that has one.
func TestDebugFlagOpensTheDebugChannel(t *testing.T) {
	t.Cleanup(func() { ui.SetDebug(false) })
	var buf bytes.Buffer
	defer ui.SetOutput(&buf, ui.Plain)()

	o, _, err := parseArgs("mount", []string{"--debug", "pelican://example/vol"}, 1, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !o.debug {
		t.Error("--debug no longer reaches the FUSE backend's protocol tracing")
	}
	ui.Debug("federation {op} took {duration}", "op", "get roots/main", "duration", "12ms")
	if !strings.Contains(buf.String(), "federation get roots/main took 12ms") {
		t.Errorf("--debug did not open the channel every backend can reach; got %q", buf.String())
	}
}

// The default is the channel closed: a user who did not ask is owed the
// output they have always had.
func TestWithoutTheFlagTheChannelStaysClosed(t *testing.T) {
	t.Cleanup(func() { ui.SetDebug(false) })
	var buf bytes.Buffer
	defer ui.SetOutput(&buf, ui.Plain)()

	o, _, err := parseArgs("mount", []string{"pelican://example/vol"}, 1, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.debug {
		t.Error("--debug defaulted to on")
	}
	ui.Debug("internal detail")
	if buf.String() != "" {
		t.Errorf("pelfs volunteered its internals: %q", buf.String())
	}
}

// --debug=false is a bool flag's other spelling and must close the
// channel rather than open it on the strength of being mentioned.
func TestDebugFalseClosesTheChannel(t *testing.T) {
	t.Cleanup(func() { ui.SetDebug(false) })
	var buf bytes.Buffer
	defer ui.SetOutput(&buf, ui.Plain)()

	ui.SetDebug(true)
	o, _, err := parseArgs("mount", []string{"--debug=false", "pelican://example/vol"}, 1, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.debug {
		t.Error("--debug=false left FUSE tracing on")
	}
	ui.Debug("internal detail")
	if buf.String() != "" {
		t.Errorf("--debug=false left the channel open: %q", buf.String())
	}
}
