// Command pelfs mounts a filesystem whose content-addressed packs and
// signed catalogs live in a Pelican federation.
//
//	pelfs init   <prefix>            create a new volume
//	pelfs shell  <prefix>            mount + subshell; exit to unmount (sealing)
//	pelfs shell  <prefix> -- <cmd>   mount + run one command; its status is ours
//	pelfs mount  <prefix> [mnt]      mount in the background (daemon)
//	pelfs umount <prefix|mnt>        stop a background mount cleanly
//	pelfs status                     list background mounts
//	pelfs gc     [--delete] <prefix> find (remove) unreferenced pack objects
//	pelfs tag    <prefix> <name>     freeze the branch head under a name
//	pelfs tag    --rm <prefix> <name> delete a tag; the next gc reclaims what it pinned
//	pelfs branch <prefix> <name>     start a second line of history at a head
//	pelfs branch --rm <prefix> <name> delete a branch (never the last one)
//	pelfs merge  <prefix> <branch>   bring another branch in; --apply to carry it out
//	pelfs fsck   <prefix>            verify a published generation
//	pelfs repack-plan <prefix>       report what a repack would rewrite
//	pelfs repack [--apply] <prefix>  rewrite mostly-dead packs, publish a generation
//	pelfs cache  [clear] <prefix>    show, or free, the local cache
//	pelfs browse [--rw] <prefix>     a page on 127.0.0.1: durability, and publish
//	pelfs rotate [--apply] <prefix>  replace the volume signing key
//	pelfs rotate --to-unsigned|--to-signed <prefix>  stop or start signing it
//	pelfs rescue [--apply] <prefix>  rebuild refs from packs after a disaster
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
	"github.com/bbockelm/pelfs/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "shell":
		code = cmdShell(os.Args[2:])
	case "mount":
		code = cmdMount(os.Args[2:])
	case "umount", "unmount":
		code = cmdUmount(os.Args[2:])
	case "status":
		code = cmdStatus(os.Args[2:])
	case "gc":
		code = cmdGC(os.Args[2:])
	case "tag":
		code = cmdTag(os.Args[2:])
	case "merge":
		code = cmdMerge(os.Args[2:])
	case "branch":
		code = cmdBranch(os.Args[2:])
	case "ctl":
		code = cmdCtl(os.Args[2:])
	case "init":
		code = cmdInit(os.Args[2:])
	case "mount-gen":
		code = cmdMountGen(os.Args[2:])
	case "fsck":
		code = cmdFsck(os.Args[2:])
	case "graft":
		code = cmdGraft(os.Args[2:])
	case "repack-plan":
		code = cmdRepackPlan(os.Args[2:])
	case "repack":
		code = cmdRepack(os.Args[2:])
	case "cache":
		code = cmdCache(os.Args[2:])
	case "browse":
		code = cmdBrowse(os.Args[2:])
	case "rotate":
		code = cmdRotate(os.Args[2:])
	case "rescue":
		code = cmdRescue(os.Args[2:])
	case "version", "--version":
		fmt.Println(version.Get())
	case "-h", "--help", "help":
		usage()
	default:
		// The usage text below is a document and stays raw; the
		// complaint about the command is a message like any other, and
		// is attributed like one.
		ui.Error("unknown command {command}", "command", os.Args[1])
		usage()
		code = 2
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintf(os.Stderr, `pelfs — a locally mountable filesystem stored in a Pelican federation

Usage:
  pelfs init   [flags] pelican://<federation>/<prefix>    create a new volume
  pelfs init   --unsigned [flags] <prefix>                create one with NO signing key,
                                                          for throwaway work; readers need
                                                          --allow-unsigned
  pelfs shell  [flags] <prefix>                           mount + subshell
  pelfs shell  [flags] <prefix> -- <command> [args...]    mount + run one command
  pelfs mount  [flags] [--rw] <prefix> [mountpoint]       background mount
  pelfs umount [--state-dir d] <prefix-or-mountpoint>     stop a background mount
  pelfs status [--state-dir d]                            list background mounts
                                                          (--state-dir where the session
                                                          was started with one)
  pelfs gc     [flags] [--delete] <prefix>                sweep unreferenced packs
  pelfs tag    [flags] <prefix> <name>                    freeze the branch head under
                                                          a name, retained until --rm
  pelfs tag    --list <prefix>                            list this volume's tags
  pelfs tag    --rm <prefix> <name>                       delete a tag; the next gc
                                                          reclaims what it was pinning
  pelfs branch [--from b|--from-tag t] <prefix> <name>    start a second line of history
                                                          at that head, advancing on its own
  pelfs branch --list <prefix>                            list this volume's branches
  pelfs branch --rm <prefix> <name>                       delete a branch; never the last
                                                          one, and gc reclaims later
  pelfs merge  [--apply] [--keep-both] <prefix> <branch>  bring another branch into this
                                                          one; reports first, and names
                                                          every conflict it cannot resolve
  pelfs mount-gen [flags] [--rw] <prefix> <mountpoint>    mount one generation
                  [--subshell] [-- <command> [args...]]   run in the mount, then unmount
  pelfs ctl    <prefix-or-mountpoint> <verb>              control a running mount
                                                          (status|stats|publish|bugreport)
  pelfs fsck   [flags] [--deep] <prefix>                  verify a published generation
  pelfs repack-plan [flags] <prefix>                      report what a repack would
                                                          rewrite, and what it would cost
  pelfs repack [--apply] [flags] <prefix>                 rewrite those packs and
                                                          publish a generation
  pelfs cache  [clear] [flags] <prefix>                   show (or free) the local
                                                          cache this volume is using
  pelfs browse [--rw] [--open] [flags] <prefix>           serve a page on 127.0.0.1 that
                                                          says what is published and what
                                                          is only on this machine, with a
                                                          publish button; Ctrl-C seals
  pelfs rotate [--apply] [flags] <prefix>                 replace the volume signing key
                                                          through the custody chain; reports
                                                          what it would break by default
  pelfs rotate --to-unsigned|--to-signed [--apply] <prefix>
                                                          stop, or start, signing this volume.
                                                          Every other reader must clear its pin
                                                          by hand either way
  pelfs rescue [--apply] [flags] <prefix>                 rebuild the refs from the packs'
                                                          superblock backups, for the day
                                                          the refs are gone; never deletes
  pelfs version                                           which build this is (quote it
                                                          in bug reports)

Common flags:
`)
	fs := flag.NewFlagSet("pelfs", flag.ContinueOnError)
	registerFlags(fs, &cmdOpts{})
	fs.PrintDefaults()
}

type cmdOpts struct {
	token            string
	stateDir         string
	snapshotInterval time.Duration
	readOnly         bool
	encryptKeyPath   string
	noLease          bool
	stealLease       bool
	// ignoreVolumeLease is about the v0.1.0 whole-volume lease object and
	// nothing else; see registerFlags for why it is not folded into
	// stealLease.
	ignoreVolumeLease bool
	noAcquireToken    bool
	insecure          bool
	debug             bool
	backend           string
	shellPath         string
	gcDelete          bool
	prefetch          string
	statsFile         string
	cacheSize         string
	noAutoRepack      bool
	noAutoGC          bool
	allowUnsigned     bool
}

func registerFlags(fs *flag.FlagSet, o *cmdOpts) {
	fs.StringVar(&o.token, "token", "", "path to a bearer-token file (default: Pelican client token discovery)")
	fs.StringVar(&o.stateDir, "state-dir", "", "directory for local state (overlay, caches, signing key); default: a persistent per-prefix directory")
	fs.DurationVar(&o.snapshotInterval, "snapshot-interval", 5*time.Minute, "how often a writable mount checkpoints its overlay into a new generation (0 seals only at unmount)")
	fs.StringVar(&o.encryptKeyPath, "encrypt-key", "", "PEM private key wrapping the volume's data keys (required again on every later mount)")
	fs.BoolVar(&o.readOnly, "ro", false, "mount read-only: no overlay, no seal")
	// The second clause is not decoration. A leased session now FENCES every
	// publish — a seal whose lease has gone stale rechecks it before doing
	// any work, and refuses if it lost the branch — and a --no-lease session
	// has nothing to fence with. It keeps exactly the guard it always had,
	// the flip's compare-and-swap, which catches a concurrent writer only
	// after the whole publish has been paid for and cannot catch one that
	// has not published yet.
	fs.BoolVar(&o.noLease, "no-lease", false, "do not take or check the advisory write lease (concurrent writers will NOT be detected, and seals are NOT fenced: publishing rests entirely on the flip's compare-and-swap against the branch head)")
	fs.BoolVar(&o.stealLease, "steal-lease", false, "take over a live lease on THIS BRANCH held by another client (use only when that client is known dead)")
	// Two flags rather than one, because the two objects have different
	// blast radii. --steal-lease is about the branch in front of you.
	// meta/lease.json is a pelfs v0.1.0 client that locks the WHOLE volume
	// and whose record does not say which branch it is writing, so
	// proceeding past it is a bet about a client you cannot see, and it
	// should have to be typed out. It ignores rather than steals: this
	// release never writes that object (internal/lease, package comment).
	fs.BoolVar(&o.ignoreVolumeLease, "ignore-volume-lease", false, "proceed past a live meta/lease.json left by a pelfs v0.1.0 client, which locks the whole volume and does not say which branch it writes")
	// Common rather than per-command, because it is a property of the
	// VOLUME and every verb that reads one has to be able to say it: a user
	// who can mount an unsigned volume but cannot fsck or gc it has a
	// volume that rots. It is the reader's consent to serve a volume with
	// no integrity root, and it deliberately does NOT override a pin — see
	// internal/refs.
	fs.BoolVar(&o.allowUnsigned, "allow-unsigned", false, "read a volume that carries no signature at all "+
		"(`pelfs init --unsigned`). Nothing about such a volume is authenticated: anyone who can write the "+
		"prefix can replace its contents undetectably. Refused on any volume this client has already seen signed")
	fs.BoolVar(&o.noAcquireToken, "no-acquire-token", false, "never run interactive token-acquisition flows; rely on discovered tokens only")
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS verification (test federations only)")
	// --debug opens a channel, so it is wired where it is defined rather
	// than at a use site: it used to reach only the FUSE library's
	// protocol tracing, which left it a silent no-op on the NFS backend
	// and on every command that never mounts anything.
	fs.BoolFunc("debug", "log what pelfs is doing internally (federation transfers, daemon startup) and, on the fuse backend, trace the FUSE kernel protocol", func(v string) error {
		on, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		o.debug = on
		ui.SetDebug(on)
		return nil
	})
	fs.StringVar(&o.backend, "backend", "auto", "how to attach the filesystem: auto, fuse, or nfs (loopback NFS server + the OS NFS client; no kext or macFUSE needed on macOS)")
	fs.StringVar(&o.shellPath, "shell", "", "shell to launch (default: $SHELL, else /bin/sh)")
	fs.StringVar(&o.prefetch, "prefetch", "none", "download the generation into the local cache at startup: none, all (blocking; refuse to start on any failure OR any grafted content), packs (blocking; make the packs local and warn that grafted bytes are not), or background")
	fs.StringVar(&o.statsFile, "stats-file", "", "write a JSON session-statistics summary to this path (default: <state-dir>/pelfs-stats.json)")
	fs.StringVar(&o.cacheSize, "cache-size", "", "byte budget for the local cache of packs, decoded chunks, catalogs and trailers (e.g. 8G); default 4G")
	fs.BoolVar(&o.noAutoRepack, "no-auto-repack", false, "do not repack in the background when the mount is idle and the branch has drifted")
	// Separate from --no-auto-repack because the two halves fail
	// differently: a repack that does not run costs storage, while a sweep
	// DELETES, so an operator who wants to hold the deletions back should
	// not have to give up the condemning as well. (And turning the repack
	// off leaves the sweep running, which is equally right: garbage no
	// repack was involved in -- an aborted publish, a deleted tag's closure
	// -- is still collectable.)
	fs.BoolVar(&o.noAutoGC, "no-auto-gc", false, "do not collect unreferenced objects in the background when the mount is idle (the sweep is `pelfs gc --delete`, with the same grace and retain-K windows and the same fail-closed rule)")
}

func parseArgs(name string, args []string, minPos, maxPos int, extra func(*flag.FlagSet, *cmdOpts)) (*cmdOpts, []string, error) {
	o := &cmdOpts{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	registerFlags(fs, o)
	if extra != nil {
		extra(fs, o)
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if fs.NArg() < minPos || fs.NArg() > maxPos {
		return nil, nil, fmt.Errorf("expected %d-%d positional arguments, got %d", minPos, maxPos, fs.NArg())
	}
	switch o.prefetch {
	case "none", "all", "packs", "background":
	default:
		return nil, nil, fmt.Errorf("--prefetch must be none, all, packs, or background")
	}
	return o, fs.Args(), nil
}

// splitCommandTail separates a trailing `-- command args...` from the
// arguments the flag package will parse.
//
// The split happens BEFORE flag parsing on purpose: Go's flag package stops
// at the first non-flag argument, so `shell --ro pfx -- ls -la`
// would otherwise reach fs.Args() as four positional arguments and the
// min/max positional check would no longer mean what it says.
func splitCommandTail(args []string) (head, tail []string, hasTail bool) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

// parseArgsWithCommand is parseArgs for the commands that accept a trailing
// `-- command args...`: everything after the separator runs inside the mount
// instead of an interactive shell. Commands without a tail keep the flag
// package's own treatment of a bare `--`.
func parseArgsWithCommand(name string, args []string, minPos, maxPos int, extra func(*flag.FlagSet, *cmdOpts)) (*cmdOpts, []string, []string, error) {
	head, tail, hasTail := splitCommandTail(args)
	if hasTail && len(tail) == 0 {
		return nil, nil, nil, errors.New("`--` must be followed by the command to run inside the mount")
	}
	o, pos, err := parseArgs(name, head, minPos, maxPos, extra)
	if err != nil {
		return nil, nil, nil, err
	}
	return o, pos, tail, nil
}

// fuseUsable reports whether this host can mount FUSE, and says why not
// when it cannot.
//
// On Linux it OPENS /dev/fuse rather than stat-ing it. The difference is
// the whole unprivileged story: on a locked-down host the device node
// exists and is root-only, so a stat says yes, the mount is attempted,
// and the user gets a permission error from three layers down with no
// idea which of the several things it could mean actually happened. The
// probe costs one open and one close, and it is the same syscall the
// mount will make.
//
// The reason is returned rather than logged because it is the only useful
// thing this function knows: "no" without it sends a user to install a
// package they already have.
func fuseUsable() (bool, string) {
	// ASKED OF THE BUILD FIRST, not of runtime.GOOS. A Windows build has
	// no FUSE frontend compiled into it at all (cmd/pelfs/fusefront.go),
	// so there is nothing for the probes below to probe, and the honest
	// answer names the missing dependency rather than the platform.
	if !fuseBuilt {
		return false, fuseUnsupported
	}
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat("/Library/Filesystems/macfuse.fs"); err != nil {
			return false, "macFUSE is not installed"
		}
		return true, ""
	case "linux":
		f, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
		switch {
		case err == nil:
			f.Close() //nolint:errcheck
			return true, ""
		case os.IsNotExist(err):
			return false, "/dev/fuse does not exist (the fuse module is not loaded, or this is a container without --device /dev/fuse)"
		case os.IsPermission(err):
			return false, "/dev/fuse exists but this user cannot open it (it is usually mode 0666; ask an administrator, or use a host that permits FUSE)"
		default:
			return false, fmt.Sprintf("/dev/fuse cannot be opened: %v", err)
		}
	default:
		return false, runtime.GOOS + " has no supported FUSE backend"
	}
}

// resolveBackend picks how the filesystem is attached: an explicit
// --backend wins; otherwise prefer native FUSE, then (on macOS, where
// mount_nfs works unprivileged with no kext) the loopback-NFS backend.
func resolveBackend(o *cmdOpts) (string, error) {
	switch o.backend {
	case "fuse":
		if ok, why := fuseUsable(); !ok {
			return "", fmt.Errorf("--backend fuse: %s", why)
		}
		return "fuse", nil
	case "nfs":
		return "nfs", nil
	case "", "auto":
		ok, why := fuseUsable()
		if ok {
			return "fuse", nil
		}
		if runtime.GOOS == "darwin" {
			return "nfs", nil
		}
		// Windows before the Linux advice below, which is about privilege
		// and would be nonsense here: there is no FUSE frontend in this
		// binary and no NFS one either, so nothing this user can do to
		// their host makes `pelfs mount` work. Everything that does not
		// mount — publish, fsck, gc, repack, cache, status — does work, and
		// saying so is the difference between a dead end and a limitation.
		if runtime.GOOS == "windows" {
			return "", fmt.Errorf("cannot mount on Windows: %s. "+
				"pelfs has no Windows frontend yet, so `mount` and `shell` are the two commands "+
				"that do not work here; everything that does not attach a filesystem does", why)
		}
		// NOT "or use --backend nfs". On Linux the loopback-NFS backend
		// needs mount(2), which needs CAP_SYS_ADMIN, so advising it here
		// sends an unprivileged user — the only kind that reaches this
		// line — to a second failure with a worse message. macOS is the
		// exception, and it is handled above: mount_nfs there works
		// without privilege or a kext, which is why that backend exists.
		return "", fmt.Errorf("cannot mount: %s. "+
			"pelfs needs FUSE on Linux and has no fallback -- the NFS backend mounts with mount(2), "+
			"which requires root. Nothing else about pelfs needs privileges: "+
			"the binary is static, the state directory is under $HOME, and no step wants sudo", why)
	default:
		return "", fmt.Errorf("unknown --backend %q (want auto, fuse, or nfs)", o.backend)
	}
}

func exitErr(err error) int {
	if err == nil {
		return 0
	}
	ui.Error("{error}", "error", err)
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	return 1
}

// mountAdvice is what to try after the OS refused a mount, or "" when
// there is nothing honest to suggest.
//
// The advice this replaced was "try --backend nfs", offered on every
// platform. On Linux that is a dead end: the NFS backend attaches with
// mount(2), which needs root, so an unprivileged user — the only kind
// who reaches this line, since FUSE is what they were already using —
// follows it to a second failure with a worse message. resolveBackend
// stopped saying it; this call site had not.
//
// macOS is the exception, and the reason that backend exists: mount_nfs
// there works with no privilege and no kernel extension, so it really is
// the thing to try when macFUSE is absent.
func mountAdvice(backend string) string {
	if runtime.GOOS == "windows" {
		return " (pelfs has no Windows frontend: the FUSE binding is Unix-only and the NFS backend " +
			"drives the platform's own mount client, which pelfs does not speak on Windows)"
	}
	if runtime.GOOS == "darwin" && backend != "nfs" {
		return " (macFUSE is not installed or not loaded; try --backend nfs, which needs no kernel extension)"
	}
	if backend == "nfs" {
		return " (the NFS backend attaches with mount(2), which requires root on Linux)"
	}
	return " (pelfs mounts with FUSE and has no fallback on this platform: the NFS backend needs root)"
}
