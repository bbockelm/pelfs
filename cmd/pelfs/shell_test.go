package main

import (
	"flag"
	"slices"
	"testing"
)

func TestSplitCommandTail(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		head    []string
		tail    []string
		hasTail bool
	}{
		{"no separator", []string{"--writeback", "pfx"}, []string{"--writeback", "pfx"}, nil, false},
		{"flags then tail", []string{"--writeback", "pfx", "--", "ls", "-la"},
			[]string{"--writeback", "pfx"}, []string{"ls", "-la"}, true},
		{"separator last", []string{"pfx", "--"}, []string{"pfx"}, []string{}, true},
		// Only the FIRST separator splits: a `--` inside the command belongs
		// to the command.
		{"nested separator", []string{"pfx", "--", "sh", "-c", "git log --"},
			[]string{"pfx"}, []string{"sh", "-c", "git log --"}, true},
		{"double-dash flags survive", []string{"--rw", "--subshell", "pfx", "mnt", "--", "make"},
			[]string{"--rw", "--subshell", "pfx", "mnt"}, []string{"make"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			head, tail, hasTail := splitCommandTail(tc.args)
			if !slices.Equal(head, tc.head) {
				t.Errorf("head = %q, want %q", head, tc.head)
			}
			if !slices.Equal(tail, tc.tail) {
				t.Errorf("tail = %q, want %q", tail, tc.tail)
			}
			if hasTail != tc.hasTail {
				t.Errorf("hasTail = %v, want %v", hasTail, tc.hasTail)
			}
		})
	}
}

// TestParseArgsWithCommand gates the argument split: the positional-count
// check must still count only real positionals, and the command must
// arrive intact.
func TestParseArgsWithCommand(t *testing.T) {
	o, pos, cmd, err := parseArgsWithCommand("shell", []string{"--ro", "pfx", "--", "ls", "-la"}, 1, 1, nil)
	if err != nil {
		t.Fatalf("shell with a command tail: %v", err)
	}
	if !o.readOnly {
		t.Error("--ro before the tail was not parsed")
	}
	if !slices.Equal(pos, []string{"pfx"}) {
		t.Errorf("positional = %q, want [pfx]", pos)
	}
	if !slices.Equal(cmd, []string{"ls", "-la"}) {
		t.Errorf("command = %q, want [ls -la]", cmd)
	}

	// Flags that belong to the COMMAND must never be parsed as pelfs flags.
	_, _, cmd, err = parseArgsWithCommand("shell", []string{"pfx", "--", "sh", "-c", "exit 3"}, 1, 1, nil)
	if err != nil {
		t.Fatalf("shell with sh -c: %v", err)
	}
	if !slices.Equal(cmd, []string{"sh", "-c", "exit 3"}) {
		t.Errorf("command = %q", cmd)
	}

	// No tail: unchanged behavior.
	_, pos, cmd, err = parseArgsWithCommand("shell", []string{"--ro", "pfx"}, 1, 1, nil)
	if err != nil {
		t.Fatalf("shell without a tail: %v", err)
	}
	if len(cmd) != 0 || !slices.Equal(pos, []string{"pfx"}) {
		t.Errorf("pos = %q, command = %q; want [pfx] and none", pos, cmd)
	}

	// A separator with nothing after it is a user error, not an empty argv.
	if _, _, _, err = parseArgsWithCommand("shell", []string{"pfx", "--"}, 1, 1, nil); err == nil {
		t.Error("`pfx --` was accepted; want an error")
	}

	// The positional check still applies to the head only.
	if _, _, _, err = parseArgsWithCommand("shell", []string{"a", "b", "--", "ls"}, 1, 1, nil); err == nil {
		t.Error("two positionals were accepted for a 1-1 command")
	}

	// mount-gen: two positionals, extra flags, and a tail.
	var rw bool
	o, pos, cmd, err = parseArgsWithCommand("mount-gen", []string{"--rw", "pfx", "/mnt", "--", "make", "-j4"}, 2, 2,
		func(fs *flag.FlagSet, _ *cmdOpts) { fs.BoolVar(&rw, "rw", false, "") })
	if err != nil {
		t.Fatalf("mount-gen with a command tail: %v", err)
	}
	if !rw || !slices.Equal(pos, []string{"pfx", "/mnt"}) || !slices.Equal(cmd, []string{"make", "-j4"}) {
		t.Errorf("rw = %v, pos = %q, command = %q", rw, pos, cmd)
	}
}

// TestParseArgsUnaffected pins the shared helper's behavior for the commands
// that take no command tail.
func TestParseArgsUnaffected(t *testing.T) {
	var del bool
	_, pos, err := parseArgs("gc", []string{"--delete", "pfx"}, 1, 1,
		func(fs *flag.FlagSet, _ *cmdOpts) { fs.BoolVar(&del, "delete", false, "") })
	if err != nil || !del || !slices.Equal(pos, []string{"pfx"}) {
		t.Fatalf("gc --delete pfx: err = %v, delete = %v, pos = %q", err, del, pos)
	}
	// `mount` takes an optional second positional; a `--` there is still the
	// flag package's own terminator.
	if _, pos, err = parseArgs("mount", []string{"--", "pfx", "/mnt"}, 1, 2, nil); err != nil {
		t.Fatalf("mount -- pfx /mnt: %v", err)
	}
	if !slices.Equal(pos, []string{"pfx", "/mnt"}) {
		t.Errorf("pos = %q, want [pfx /mnt]", pos)
	}
}
