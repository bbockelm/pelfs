package version

import (
	"strings"
	"testing"
)

// The whole point is that a bug report can say which build produced it,
// so the one thing that must never happen is a build claiming to be a
// version it is not.
func TestShortNeverInventsAVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   Info
		want string
	}{
		{"nothing known", Info{}, "unknown"},
		{"release", Info{Release: "v0.1.0"}, "v0.1.0"},
		{"dirty release", Info{Release: "v0.1.0", Modified: true}, "v0.1.0+dirty"},
		{"revision only", Info{Revision: "29c274a1b2c3d4e5f6"}, "29c274a1b2c3"},
		{"dirty revision", Info{Revision: "29c274a1b2c3d4e5f6", Modified: true}, "29c274a1b2c3+dirty"},
		{"short revision is not padded", Info{Revision: "abc123"}, "abc123"},
	} {
		if got := tc.in.Short(); got != tc.want {
			t.Errorf("%s: Short() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A dirty tree must be visible wherever the version is, because its
// behaviour matches no commit anyone else can check out.
func TestADirtyBuildSaysSoEverywhere(t *testing.T) {
	i := Info{Release: "v0.1.0", Revision: "deadbeefcafe", Modified: true, Go: "go1.26.0", OS: "darwin", Arch: "arm64"}
	if !strings.Contains(i.Short(), "dirty") {
		t.Errorf("Short() = %q, which hides a dirty tree", i.Short())
	}
	if !strings.Contains(i.String(), "dirty") {
		t.Errorf("String() = %q, which hides a dirty tree", i.String())
	}
	if m := i.Map(); m["modified"] != true {
		t.Errorf("Map()[modified] = %v, want true", m["modified"])
	}
}

// Empty fields are KEPT in the JSON. A bug report that says
// "revision: unknown" is more useful than one that silently omits it,
// because the reader cannot tell an omitted field from an old schema.
func TestMapKeepsUnknownFields(t *testing.T) {
	m := Info{}.Map()
	for _, k := range []string{"version", "release", "revision", "modified", "time", "go", "os", "arch"} {
		if _, ok := m[k]; !ok {
			t.Errorf("Map() dropped %q when it was unknown", k)
		}
	}
	if m["version"] != "unknown" {
		t.Errorf("Map()[version] = %v, want \"unknown\"", m["version"])
	}
}

// The real build must produce something, whatever the harness. A test
// binary has no VCS stamp, so this asserts only that nothing panics and
// the toolchain fields are present — the parts that are always knowable.
func TestGetDescribesTheRunningBuild(t *testing.T) {
	i := Get()
	if i.Go == "" || i.OS == "" || i.Arch == "" {
		t.Fatalf("Get() = %+v, missing toolchain fields", i)
	}
	if i.Short() == "" {
		t.Error("Short() is empty; it must always name something, even \"unknown\"")
	}
	t.Logf("%s", i)
}

// The toolchain synthesizes a version for an untagged build that just
// re-encodes the revision, and marks a dirty tree inside the string. Both
// have to be recognised: reporting a pseudo-version as a release dresses
// a development build up as a numbered one, and passing the marker
// through produces "v0.1.0+dirty+dirty".
func TestRealVersionRejectsPseudoVersionsAndStripsTheDirtyMarker(t *testing.T) {
	for _, tc := range []struct {
		in          string
		wantRelease string
		wantDirty   bool
	}{
		{"v0.1.0", "v0.1.0", false},
		{"v0.1.0+dirty", "v0.1.0", true},
		{"(devel)", "", false},
		{"", "", false},
		{"v0.0.0-20260820001322-29c274a6eb01", "", false},
		{"v0.0.0-20260820001322-29c274a6eb01+dirty", "", true},
		{"v1.2.3-0.20260820001322-29c274a6eb01", "", false},
		{"v1.2.3-rc1", "v1.2.3-rc1", false},
	} {
		gotRelease, gotDirty := realVersion(tc.in)
		if gotRelease != tc.wantRelease || gotDirty != tc.wantDirty {
			t.Errorf("realVersion(%q) = (%q, %v), want (%q, %v)",
				tc.in, gotRelease, gotDirty, tc.wantRelease, tc.wantDirty)
		}
	}
}
