package merge

import "testing"

func TestConflictNameKeepsTheExtension(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"notes.txt", "notes (from dev).txt"},
		{"archive.tar.gz", "archive.tar (from dev).gz"},
		{"Makefile", "Makefile (from dev)"},
		{".gitignore", ".gitignore (from dev)"},
		{"a.b.c.d", "a.b.c (from dev).d"},
	} {
		if got := ConflictName(tc.in, "dev"); got != tc.want {
			t.Errorf("ConflictName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
