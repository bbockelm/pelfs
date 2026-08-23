package main

import (
	"flag"
	"reflect"
	"testing"
)

// APPTAINER'S COMMAND LINE, AS AN ARGUMENT-HANDLING TEST.
//
// A --fusemount driver is invoked as `<driver> /dev/fd/N -f` with a
// scrubbed environment (docs/design-apptainer.md). Both halves of that
// used to be fatal here: the trailing -f arrived as a third positional and
// died on the arity check, and the mountpoint was mkdir'd. This file pins
// the argument handling; the mount itself is pinned in the container
// harness (scripts/apptainer-test.sh).

func TestHoistForegroundAcceptsATrailingFlag(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "apptainer's own shape",
			in:   []string{"--ro", "--state-dir", "/scratch", "pelican://fed/pfx", "/dev/fd/3", "-f"},
			want: []string{"-foreground", "--ro", "--state-dir", "/scratch", "pelican://fed/pfx", "/dev/fd/3"},
		},
		{
			name: "the long spellings, in either position",
			in:   []string{"--foreground", "pfx", "/mnt", "-foreground"},
			want: []string{"-foreground", "pfx", "/mnt"},
		},
		{
			name: "nothing to hoist is returned untouched",
			in:   []string{"--ro", "pfx", "/mnt"},
			want: []string{"--ro", "pfx", "/mnt"},
		},
	} {
		if got := hoistForeground(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: hoistForeground(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// The arity check is what actually broke, so assert on it rather than on
// the hoist alone: two positionals, in the right order, with -f accepted.
func TestMountGenParsesApptainersArgv(t *testing.T) {
	args := hoistForeground([]string{"--ro", "pelican://fed/pfx", "/dev/fd/3", "-f"})
	_, pos, command, err := parseArgsWithCommand("mount-gen", args, 2, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.Bool("foreground", false, "")
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := []string{"pelican://fed/pfx", "/dev/fd/3"}; !reflect.DeepEqual(pos, want) {
		t.Errorf("positionals = %q, want %q", pos, want)
	}
	if len(command) != 0 {
		t.Errorf("command tail = %q, want none", command)
	}
}

// A `-f` inside a `-- command args...` tail belongs to the command, and
// hoisting it would silently rewrite what the user asked to run. The tail
// is split off before the hoist for exactly that reason.
func TestForegroundHoistLeavesTheCommandTailAlone(t *testing.T) {
	head, tail, hasTail := splitCommandTail([]string{"--rw", "pfx", "/mnt", "--", "rm", "-f", "junk"})
	if !hasTail {
		t.Fatal("no command tail found")
	}
	if got := hoistForeground(head); !reflect.DeepEqual(got, head) {
		t.Errorf("hoisted from the head: %q", got)
	}
	if want := []string{"rm", "-f", "junk"}; !reflect.DeepEqual(tail, want) {
		t.Errorf("tail = %q, want %q", tail, want)
	}
}

// The backend for a passed descriptor: FUSE without probing /dev/fuse
// (there is nothing to probe — the mount exists), and never NFS, which
// attaches by calling mount(2) on a directory.
func TestPassedFDBackend(t *testing.T) {
	for _, in := range []string{"", "auto", "fuse"} {
		got, err := passedFDBackend(&cmdOpts{backend: in})
		if err != nil || got != "fuse" {
			t.Errorf("passedFDBackend(%q) = %q, %v; want fuse, nil", in, got, err)
		}
	}
	if _, err := passedFDBackend(&cmdOpts{backend: "nfs"}); err == nil {
		t.Error("--backend nfs on a passed descriptor was accepted")
	}
}

// A passed descriptor has no path, so there is nowhere to run a subshell
// or a command: refused up front, before any federation round trip, rather
// than failing inside the payload's chdir.
func TestPassedFDRefusesASubshell(t *testing.T) {
	for _, args := range [][]string{
		{"--ro", "--subshell", "pelican://fed/pfx", "/dev/fd/3"},
		{"--ro", "pelican://fed/pfx", "/dev/fd/3", "--", "ls"},
	} {
		if code := cmdMountGen(args); code == 0 {
			t.Errorf("cmdMountGen(%q) = 0, want a refusal", args)
		}
	}
	// The same command line against a real directory must NOT be refused
	// here — it fails later, on the federation, which is a different error.
	if code := cmdMountGen([]string{"--ro", "--backend", "nfs", "pelican://fed/pfx", "/dev/fd/3"}); code == 0 {
		t.Error("--backend nfs on a passed descriptor was accepted")
	}
}
