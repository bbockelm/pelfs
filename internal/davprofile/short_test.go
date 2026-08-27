package davprofile

import "testing"

// TestShortVolume is the one piece of formatting logic in a package that is
// otherwise plist plumbing, so it gets its own rows — and it is in the
// INTERNAL test package because the function is unexported and there is no
// reason to export a name-shortener.
func TestShortVolume(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"pelican://osg-htc.org/user/bbockelman", "osg-htc.org/user/bbockelman"},
		{"https://example.org/vol/", "example.org/vol"},
		{"", ""},
		{"  ", ""},
		// No scheme at all is not an error; it is just a shorter string.
		{"example.org/vol", "example.org/vol"},
		// Truncated from the FRONT: the tail is what differs between two
		// volumes in one federation, and the head is what does not.
		{"pelican://osg-htc.org/very/deep/tree/that/keeps/going/and/going/and/going/leaf",
			"...p/tree/that/keeps/going/and/going/and/going/leaf"},
	} {
		if got := shortVolume(tc.in); got != tc.want {
			t.Errorf("shortVolume(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// A multi-byte volume truncated at a byte boundary would put an invalid
	// rune in a plist string, which is a parse error in the client rather
	// than a cosmetic problem.
	long := "pelican://example.org/" + string([]rune("ünïcödé-påth-thät-ïs-lông-enöugh-tö-be-cüt-öff-sömewhere"))
	if got := shortVolume(long); !utf8ValidForTest(got) {
		t.Errorf("shortVolume(%q) = %q, which is not valid UTF-8", long, got)
	}
}

func utf8ValidForTest(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}
