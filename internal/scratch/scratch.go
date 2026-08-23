// Package scratch names, and reclaims, the per-run working directories a
// pelfs process creates inside a volume's state directory.
//
// Three operations spool gigabytes onto local disk before they upload
// anything: a seal (packs being built), a checkpoint (the frozen overlay
// it publishes), and a repack (the packs it rewrites). All three clean up
// on the happy path. None of them can clean up after a `kill -9`, and the
// state directory outlives the process, so what a killed run left behind
// is still there at the next mount — which is what this package is for.
//
// WHY THE NAME CARRIES THE OWNER. A sweeper that deletes by pattern alone
// cannot tell a dead run's spool from a live one's, and the live one is
// mid-upload with a file open in it. The owning pid is therefore part of
// the directory NAME, which makes ownership atomic with creation: there is
// no window between mkdir and a stamp file in which a crash produces an
// unattributable directory. It is the same trick packstore plays with pack
// names, where the creation stamp in the name is what lets GC's age guard
// work with no coordination between writers and the sweep.
//
// WHY LIVENESS RATHER THAN THE LEASE. A state directory is single-writer
// by lease, so it is tempting to treat "I hold the lease" as "nothing else
// is running". It is not the same statement. A lease says who SHOULD be
// writing; it is a record in the federation, and a holder that was killed
// leaves it standing until it expires or is stolen — which is exactly the
// case whose scratch must be reclaimed. In the other direction, processes
// that hold no writable lease at all still make scratch here: a read-only
// mount of the same state directory, a `pelfs repack` running under a
// maintenance lease on another branch, a merge. So the question this
// sweeper asks is not "who is entitled to write" but "who is still
// running", and only the OS can answer that.
//
// WHAT PIDAlive PROMISES, since the OS-specific halves live in
// pidalive_unix.go and pidalive_windows.go and the contract has to hold
// for both. It is deliberately lopsided: FALSE MEANS THIS PACKAGE
// DELETES A DIRECTORY, so false is the answer that has to be earned, and
// it is returned only where the OS positively says there is no such
// process (ESRCH; ERROR_INVALID_PARAMETER from OpenProcess). Every other
// outcome — the process exists and belongs to somebody else, the OS
// refuses to say, the call fails for a reason this code did not
// anticipate — reports ALIVE. The cost of a wrong "alive" is a directory
// swept a week later by the reuse-age backstop; the cost of a wrong
// "dead" is a live session's spool deleted from under it mid-upload.
//
// (cmd/pelfs's own pidAlive answers a different question — whether a
// mount this user started is still up — and is stricter on purpose.)
package scratch

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The scratch families. Each is a directory-name prefix in a spool
// directory, and each is created by exactly one operation.
const (
	// Publish is a seal's pack spool: the gigabytes case, since packs are
	// built here before they go on the wire.
	Publish = "publish"
	// Snapshot is the frozen overlay a checkpoint publishes from: one file
	// per dirty inode.
	Snapshot = "snapshot"
	// Repack is the spool a repack rewrites condemned packs into.
	Repack = "repack"
)

// Families is every prefix Sweep collects.
var Families = []string{Publish, Snapshot, Repack}

// legacyNames are fixed directory names that earlier releases used for
// scratch and never removed. They carry no owner, so they are reclaimed
// on the age guard alone; no current version writes them.
var legacyNames = map[string]bool{"repack": true}

const (
	// DefaultOrphanAge is how long an UNOWNED scratch directory has to sit
	// untouched before it is collected. Unowned means the name names no
	// pid: a directory an older release created, or one a foreign tool
	// dropped here. Nothing can be asked about its owner, so the only
	// honest guard is time, and it is set well past the longest plausible
	// single seal or repack rather than at the shortest that would pass a
	// test.
	DefaultOrphanAge = 24 * time.Hour
	// DefaultReuseAge is the backstop under the one hole pid ownership
	// has: pids are reused, freely so across a reboot — and far more
	// freely than that on Windows, where they are handle-table indices
	// handed out in small multiples of four (see pidalive_windows.go) — and
	// a stranded directory whose number has been inherited by some
	// long-lived daemon
	// would otherwise be protected forever. A live run refreshes its own
	// directory's mtime continuously — a spool is written to for as long
	// as it is used — so this expires only for a directory that has been
	// untouched for a week while its supposed owner runs.
	DefaultReuseAge = 7 * 24 * time.Hour
)

// Make creates a scratch directory for this process, in parent, named so
// that a later sweep can tell whether its owner is still running. An empty
// parent takes the system temporary directory, as os.MkdirTemp does.
func Make(parent, family string) (string, error) {
	return os.MkdirTemp(parent, family+"-"+strconv.Itoa(os.Getpid())+"-*")
}

// Owner reports the pid a scratch directory name carries. A name from an
// older release, or any name that is not this package's, has no owner and
// reports false — which is not an error, it is the case DefaultOrphanAge
// covers.
func Owner(name string) (int, bool) {
	for _, f := range Families {
		if !strings.HasPrefix(name, f+"-") {
			continue
		}
		rest := name[len(f)+1:]
		cut := strings.IndexByte(rest, '-')
		if cut <= 0 {
			return 0, false // `publish-1234567` — an older release's name
		}
		pid, err := strconv.Atoi(rest[:cut])
		if err != nil || pid <= 0 {
			return 0, false
		}
		return pid, true
	}
	return 0, false
}

// Options tunes a sweep. The zero value is the production setting; tests
// substitute a clock and a liveness oracle rather than creating processes.
type Options struct {
	Now       time.Time
	OrphanAge time.Duration
	ReuseAge  time.Duration
	Alive     func(pid int) bool
}

func (o *Options) defaults() {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.OrphanAge <= 0 {
		o.OrphanAge = DefaultOrphanAge
	}
	if o.ReuseAge <= 0 {
		o.ReuseAge = DefaultReuseAge
	}
	if o.Alive == nil {
		o.Alive = PIDAlive
	}
}

// Reclaimed is what a sweep freed. It is returned rather than logged so
// that the caller reports it in its own voice — and so that a sweep that
// found nothing says nothing.
type Reclaimed struct {
	Dirs  int
	Bytes int64
	// Names are the directories collected, for the log line and for a
	// test that wants to say which one.
	Names []string
	// Kept counts directories left alone because their owner is still
	// running or their guard has not expired.
	Kept int
}

// Sweep collects the scratch directories in spool that no running process
// owns. It is safe to point at a directory that holds no scratch, safe to
// run while other mounts are up, and safe to run concurrently with itself:
// what it deletes is deleted whole, by name, and a name it loses a race
// for is simply one it did not collect.
//
// Errors are collected, not fatal: one undeletable directory must not stop
// the sweep from reclaiming the rest.
func Sweep(spool string, o Options) (Reclaimed, error) {
	o.defaults()
	var got Reclaimed
	ents, err := os.ReadDir(spool)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return got, nil
		}
		return got, err
	}
	var firstErr error
	for _, e := range ents {
		if !e.IsDir() || !isScratch(e.Name()) {
			continue
		}
		dir := filepath.Join(spool, e.Name())
		if !collectible(dir, e.Name(), o) {
			got.Kept++
			continue
		}
		n := dirBytes(dir)
		if err := os.RemoveAll(dir); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		got.Dirs++
		got.Bytes += n
		got.Names = append(got.Names, e.Name())
	}
	return got, firstErr
}

func isScratch(name string) bool {
	if legacyNames[name] {
		return true
	}
	for _, f := range Families {
		if strings.HasPrefix(name, f+"-") {
			return true
		}
	}
	return false
}

// collectible is the whole decision, in one place so that the three cases
// can be read against each other.
func collectible(dir, name string, o Options) bool {
	pid, owned := Owner(name)
	age := idleFor(dir, o.Now)
	switch {
	case !owned:
		// Nobody to ask. Time is the only guard there is.
		return age >= o.OrphanAge
	case !o.Alive(pid):
		// The owner is gone and cannot come back: pids are not resurrected.
		// This is the crash case, and it is collected immediately —
		// waiting out an age guard here would mean a mount that comes up
		// straight after a `kill -9` leaves the gigabytes it just found.
		return true
	default:
		// Somebody is running under that number. Ordinarily it is the
		// owner, mid-seal, and this is the case the sweep exists to be
		// careful about. See DefaultReuseAge for the one exception.
		return age >= o.ReuseAge
	}
}

// idleFor is how long nothing has written to the directory. The mtime of
// the directory itself moves whenever an entry is created or removed in
// it, so a live spool cutting packs stays young, and a stranded one is
// frozen at the instant its process died — which is the measurement both
// guards want. Unreadable takes zero, so a directory that cannot be
// stat'ed is treated as brand new and left alone.
func idleFor(dir string, now time.Time) time.Duration {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0
	}
	if d := now.Sub(fi.ModTime()); d > 0 {
		return d
	}
	return 0
}

// dirBytes is what the directory holds, measured before it is deleted
// because afterwards nobody can say. Best effort: a file that vanishes
// mid-walk contributes nothing, which is right — it is not being
// reclaimed by this sweep.
func dirBytes(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a partial measurement beats none
		}
		if fi, err := d.Info(); err == nil {
			total += fi.Size()
		}
		return nil
	})
	return total
}
