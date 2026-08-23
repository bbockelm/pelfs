package webui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ONE DURABILITY VOCABULARY, ON TWO SURFACES.
//
// `pelfs browse` serves this bundle's file manager at `/` and M1's
// hand-written connection page (cmd/pelfs/browse.html) at `/connect`. Both
// answer the same question -- "is my data in the federation yet" -- from the
// same `/events` snapshot, and they must answer it in the same words and with
// the same glyphs.
//
// THIS TEST IS THE RECONCILIATION, and it is worth saying what it is not.
// Neither panel is the other's source: both are CLIENTS of the server's
// snapshot, so there is one answer with two renderings rather than two
// answers that have to be kept in agreement. What could still drift is the
// WORDING -- and a reviewer reading a diff of one file cannot see that it now
// disagrees with the other. Hence a test that reads both.
//
// The alternative was to have one panel link to the other and delete the
// second rendering. It was rejected: the whole trap this design closes is a
// finished drag-and-drop nobody publishes, and a user who has to follow a
// link to read the sentence is a user who does not read it.
//
// The failure this prevents is not cosmetic. docs/design-webui.md names the
// one ambiguity that must never reach the screen: "a file that looks uploaded
// and is not in the federation is the worst possible ambiguity for this
// audience, because the user's next action is to close the laptop and tell a
// collaborator the data is there". Two surfaces that render that distinction
// DIFFERENTLY -- a check on one, a dot on the other; "staged" here, "pending"
// there -- reintroduce exactly that ambiguity by a slower route, and no
// reviewer diffing one file would see it.
//
// So the vocabulary lives in webui/frontend/src/durability.ts and in
// cmd/pelfs/browse.html, and this test is what makes them one vocabulary
// rather than two copies. It reads SOURCE, deliberately: the built bundle
// minifies identifiers but not string literals, and the source is where a
// person edits.
func TestTheTwoSurfacesShareOneDurabilityVocabulary(t *testing.T) {
	page := readRepoFile(t, "cmd", "pelfs", "browse.html")
	app := readRepoFile(t, "webui", "frontend", "src", "durability.ts")

	// The three glyphs, as literal characters. They are three DIFFERENT
	// characters on purpose: colour alone would fail roughly one man in
	// twelve, so the shape carries the meaning.
	glyphs := map[string]string{
		"staged":    "●",
		"sending":   "◔",
		"published": "✓",
	}
	seen := map[string]string{}
	for name, glyph := range glyphs {
		if !strings.Contains(page, glyph) {
			t.Errorf("cmd/pelfs/browse.html no longer contains the %q glyph %q", name, glyph)
		}
		if !strings.Contains(app, glyph) {
			t.Errorf("webui/frontend/src/durability.ts no longer contains the %q glyph %q\n"+
				"The two surfaces must render the same three characters; see this test's comment.",
				name, glyph)
		}
		if other, clash := seen[glyph]; clash {
			t.Errorf("the %q and %q states use the SAME glyph %q; the whole panel exists to make "+
				"those two unmistakable", name, other, glyph)
		}
		seen[glyph] = name
	}

	// The sentences a user reads. Not the whole prose -- these are the
	// phrases that carry the distinction, and rewording one surface's copy of
	// them without the other is the drift this test catches.
	for _, phrase := range []string{
		"on this machine only",
		"in the federation",
		"nothing staged",
		"next automatic publish in",
		// The idle clause. It is the promise that closing the tab publishes
		// rather than abandons, and it was on the connection page only until
		// the wiring pass -- so the surface that can actually stage files was
		// the one that did not make the promise.
		"after this tab closes",
		"(nothing to publish)",
		"(read-only session — restart with --rw to publish)",
	} {
		if !strings.Contains(page, phrase) {
			t.Errorf("cmd/pelfs/browse.html no longer says %q", phrase)
		}
		if !strings.Contains(app, phrase) {
			t.Errorf("webui/frontend/src/durability.ts no longer says %q\n"+
				"Both surfaces say it, or neither does.", phrase)
		}
	}

	// The three values of data-durability, which are the suite's handle on
	// all of the above (webui/frontend/tests/durability.spec.ts).
	for _, state := range []string{"unknown", "staged", "published"} {
		if !strings.Contains(page, `"`+state+`"`) {
			t.Errorf("cmd/pelfs/browse.html no longer produces data-durability=%q", state)
		}
		if !strings.Contains(app, `"`+state+`"`) {
			t.Errorf("webui/frontend/src/durability.ts no longer produces data-durability=%q", state)
		}
	}

	// And the four lease states, which are the control socket's own
	// vocabulary and must not become three or five on one side only.
	for _, lease := range []string{"stale", "interrupted", "lost"} {
		if !strings.Contains(page, lease+":") && !strings.Contains(page, lease+" :") {
			t.Errorf("cmd/pelfs/browse.html no longer words the %q lease state", lease)
		}
		if !strings.Contains(app, lease+":") {
			t.Errorf("webui/frontend/src/durability.ts no longer words the %q lease state", lease)
		}
	}
}

// readRepoFile reads a file from the repository root, which is two levels up
// from this package. A test that reaches outside its own directory is worth a
// comment: the thing under test here is an agreement BETWEEN two directories,
// so it cannot live inside either one.
func readRepoFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}
