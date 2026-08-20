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
//	pelfs fsck   <prefix>            verify a published generation
//	pelfs repack-plan <prefix>       report what a repack would rewrite
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
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
	case "ctl":
		code = cmdCtl(os.Args[2:])
	case "init":
		code = cmdInit(os.Args[2:])
	case "mount-gen":
		code = cmdMountGen(os.Args[2:])
	case "fsck":
		code = cmdFsck(os.Args[2:])
	case "repack-plan":
		code = cmdRepackPlan(os.Args[2:])
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
  pelfs shell  [flags] <prefix>                           mount + subshell
  pelfs shell  [flags] <prefix> -- <command> [args...]    mount + run one command
  pelfs mount  [flags] [--rw] <prefix> [mountpoint]       background mount
  pelfs umount <prefix-or-mountpoint>                     stop a background mount
  pelfs status                                            list background mounts
  pelfs gc     [flags] [--delete] <prefix>                sweep unreferenced packs
  pelfs mount-gen [flags] [--rw] <prefix> <mountpoint>    mount one generation
                  [--subshell] [-- <command> [args...]]   run in the mount, then unmount
  pelfs ctl    <prefix-or-mountpoint> <verb>              control a running mount
                                                          (status|stats|publish|bugreport)
  pelfs fsck   [flags] [--deep] <prefix>                  verify a published generation
  pelfs repack-plan [flags] <prefix>                      report what a repack would
                                                          rewrite, and what it would cost
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
	noAcquireToken   bool
	insecure         bool
	debug            bool
	backend          string
	shellPath        string
	gcDelete         bool
	prefetch         string
	statsFile        string
}

func registerFlags(fs *flag.FlagSet, o *cmdOpts) {
	fs.StringVar(&o.token, "token", "", "path to a bearer-token file (default: Pelican client token discovery)")
	fs.StringVar(&o.stateDir, "state-dir", "", "directory for local state (overlay, caches, signing key); default: a persistent per-prefix directory")
	fs.DurationVar(&o.snapshotInterval, "snapshot-interval", 5*time.Minute, "how often a writable mount checkpoints its overlay into a new generation (0 seals only at unmount)")
	fs.StringVar(&o.encryptKeyPath, "encrypt-key", "", "PEM private key wrapping the volume's data keys (required again on every later mount)")
	fs.BoolVar(&o.readOnly, "ro", false, "mount read-only: no overlay, no seal")
	fs.BoolVar(&o.noLease, "no-lease", false, "do not take or check the advisory mount lease (concurrent writers will NOT be detected)")
	fs.BoolVar(&o.stealLease, "steal-lease", false, "take over a live lease held by another client (use only when that client is known dead)")
	fs.BoolVar(&o.noAcquireToken, "no-acquire-token", false, "never run interactive token-acquisition flows; rely on discovered tokens only")
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS verification (test federations only)")
	fs.BoolVar(&o.debug, "debug", false, "verbose logging")
	fs.StringVar(&o.backend, "backend", "auto", "how to attach the filesystem: auto, fuse, or nfs (loopback NFS server + the OS NFS client; no kext or macFUSE needed on macOS)")
	fs.StringVar(&o.shellPath, "shell", "", "shell to launch (default: $SHELL, else /bin/sh)")
	fs.StringVar(&o.prefetch, "prefetch", "none", "download the generation into the local cache at startup: none, all (blocking; refuse to start on any failure), or background")
	fs.StringVar(&o.statsFile, "stats-file", "", "write a JSON session-statistics summary to this path (default: <state-dir>/pelfs-stats.json)")
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
	if o.prefetch != "none" && o.prefetch != "all" && o.prefetch != "background" {
		return nil, nil, fmt.Errorf("--prefetch must be none, all, or background")
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

// fuseUsable reports whether this host can plausibly mount FUSE.
func fuseUsable() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := os.Stat("/Library/Filesystems/macfuse.fs")
		return err == nil
	case "linux":
		_, err := os.Stat("/dev/fuse")
		return err == nil
	default:
		return false
	}
}

// resolveBackend picks how the filesystem is attached: an explicit
// --backend wins; otherwise prefer native FUSE, then (on macOS, where
// mount_nfs works unprivileged with no kext) the loopback-NFS backend.
func resolveBackend(o *cmdOpts) (string, error) {
	switch o.backend {
	case "fuse":
		if !fuseUsable() {
			return "", errors.New("--backend fuse: FUSE is not available on this host")
		}
		return "fuse", nil
	case "nfs":
		return "nfs", nil
	case "", "auto":
		if fuseUsable() {
			return "fuse", nil
		}
		if runtime.GOOS == "darwin" {
			return "nfs", nil
		}
		return "", errors.New("no usable mount backend: install FUSE, or use --backend nfs")
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
