// Package version reports which pelfs this is.
//
// It exists for BUG REPORTS. A user hits a stall, runs `pelfs ctl …
// bugreport`, and sends a tarball; without a version in it, every
// subsequent question — is this the build with the packer fix, does this
// binary predate the streaming sweep — is a guess. Diagnosis has already
// been slowed once by not having it.
//
// Nothing here is configured at build time by default. Go stamps a
// binary built from a git checkout with the revision, the commit time and
// whether the tree was dirty (runtime/debug, vcs.*), and a binary
// installed with `go install …@v1.2.3` with the module version. Both are
// free and neither needs a build script to remember a flag — which is
// what makes the answer trustworthy: a build that forgot to pass a flag
// still reports honestly rather than reporting the last release's number.
//
// The ldflags override exists for release builds from a tarball, where
// there is no VCS to read. It is a fallback, not the mechanism.
package version

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// release is set at link time for builds with no VCS to read:
//
//	go build -ldflags "-X github.com/bbockelm/pelfs/internal/version.release=v0.1.0"
var release string

// Info is everything known about this build. Fields are empty rather than
// absent when unknown: a bug report saying "revision: unknown" is more
// useful than one that quietly omits the line.
type Info struct {
	// Release is the tagged version when there is one, the module
	// version for a `go install …@version` build, or empty.
	Release string
	// Revision is the VCS commit, and Modified reports a dirty tree.
	// A dirty build is worth shouting about in a bug report: its
	// behaviour matches no commit anyone else can check out.
	Revision string
	Modified bool
	// Time is the commit time, RFC3339, for a VCS build.
	Time string
	// Go, OS and Arch describe the toolchain and target.
	Go, OS, Arch string
}

// pseudoVersion matches the version the toolchain synthesizes for a
// build with no tag: a timestamp and the revision, which is exactly what
// Revision already reports. Reporting it as a RELEASE would dress a
// development build up as a numbered one.
//
// The separator before the timestamp is a dash with no base tag
// (v0.0.0-<ts>-<rev>) and a DOT when there is one
// (v1.2.3-0.<ts>-<rev>), so both have to be accepted — matching only the
// dash form lets every pseudo-version derived from a real tag through.
var pseudoVersion = regexp.MustCompile(`[-.][0-9]{14}-[0-9a-f]{12}$`)

// realVersion reduces a module version to a release if it is one, and
// reports whether it carried the toolchain's dirty marker. That marker
// has to be stripped rather than passed through: Short appends its own,
// and a version reading "v0.1.0+dirty+dirty" is a version nobody trusts.
func realVersion(v string) (release string, dirty bool) {
	if s := strings.TrimSuffix(v, "+dirty"); s != v {
		v, dirty = s, true
	}
	if v == "" || v == "(devel)" || pseudoVersion.MatchString(v) {
		return "", dirty
	}
	return v, dirty
}

var get = sync.OnceValue(func() Info {
	i := Info{Release: release, Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return i
	}
	if v, dirty := realVersion(bi.Main.Version); i.Release == "" && v != "" {
		i.Release = v
		i.Modified = i.Modified || dirty
	} else if dirty {
		i.Modified = true
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			i.Revision = s.Value
		case "vcs.time":
			i.Time = s.Value
		case "vcs.modified":
			i.Modified = s.Value == "true"
		}
	}
	return i
})

// Get returns this build's identity.
func Get() Info { return get() }

// Short is the one-token answer: a release if there is one, else a short
// revision, else "unknown". A dirty tree is marked, because a build that
// matches no commit must not be mistaken for one that does.
func (i Info) Short() string {
	switch {
	case i.Release != "":
		s := i.Release
		if i.Modified {
			s += "+dirty"
		}
		return s
	case i.Revision != "":
		s := i.Revision
		if len(s) > 12 {
			s = s[:12]
		}
		if i.Modified {
			s += "+dirty"
		}
		return s
	default:
		return "unknown"
	}
}

// String is the line `pelfs version` prints and the line a bug report
// carries.
func (i Info) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "pelfs %s", i.Short())
	var paren []string
	if i.Revision != "" && i.Release != "" {
		rev := i.Revision
		if len(rev) > 12 {
			rev = rev[:12]
		}
		paren = append(paren, "revision "+rev)
	}
	if i.Time != "" {
		paren = append(paren, "committed "+i.Time)
	}
	if len(paren) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(paren, ", "))
	}
	fmt.Fprintf(&b, "\n%s %s/%s", i.Go, i.OS, i.Arch)
	return b.String()
}

// Map is Info for a JSON document, with the same fields under snake_case
// keys. Empty fields are kept (see Info).
func (i Info) Map() map[string]any {
	return map[string]any{
		"version":  i.Short(),
		"release":  i.Release,
		"revision": i.Revision,
		"modified": i.Modified,
		"time":     i.Time,
		"go":       i.Go,
		"os":       i.OS,
		"arch":     i.Arch,
	}
}
