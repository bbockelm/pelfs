package superblock_test

import (
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// The pack set is stated ONE way. A head carrying both an inline pack list
// and manifest refs is the shape where a reader (which prefers the
// manifest) and a sweep can disagree about what the volume references —
// and the inline list is the one that loses, silently, so the packs it
// alone named are deleted.
func TestValidateRejectsBothPackShapes(t *testing.T) {
	both := &superblock.Superblock{
		Generation: 7,
		PackList:   []superblock.PackEntry{{Name: "packs/0001", Size: 10}},
		Manifests:  []superblock.ManifestRef{{Name: "aa", Size: 20, Packs: 1}},
	}
	err := both.Validate()
	if err == nil {
		t.Fatal("a superblock stating its pack set both ways validated; it must never become a branch head")
	}
	// The message has to name the generation and both counts: the operator
	// reading it has a seal that just refused and no other clue which
	// document it was.
	for _, want := range []string{"generation 7", "1 inline pack entries", "1 manifest ref"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestValidateAcceptsEitherShapeAlone(t *testing.T) {
	for _, tc := range []struct {
		what string
		sb   *superblock.Superblock
	}{
		{"inline", &superblock.Superblock{PackList: []superblock.PackEntry{{Name: "packs/0001"}}}},
		{"manifest", &superblock.Superblock{Manifests: []superblock.ManifestRef{{Name: "aa"}}}},
		// A volume with no data yet has neither, and InitVolume publishes
		// exactly that.
		{"empty", &superblock.Superblock{}},
	} {
		if err := tc.sb.Validate(); err != nil {
			t.Errorf("%s generation rejected: %v", tc.what, err)
		}
	}
}
