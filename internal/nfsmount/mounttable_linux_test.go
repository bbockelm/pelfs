//go:build linux

package nfsmount

import "testing"

// /proc/self/mounts in the format the kernel writes it, including the two
// rows that make the parser more than a Fields call: an NFS mount whose source carries the
// server and export, and a mountpoint with a space in it, which the kernel
// writes as \040 and which is exactly the shape a Finder-style volume name
// produces.
const procMountsFixture = `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/nvme0n1p2 / ext4 rw,relatime 0 0
127.0.0.1:/ /home/x/.local/state/pelfs/vol-abc/mnt nfs rw,vers=3,port=54321 0 0
127.0.0.1:/Survey\040Data /home/x/Volumes/Survey\040Data nfs rw,vers=3 0 0
tmpfs /run/user/1000 tmpfs rw,nosuid,nodev,relatime 0 0
`

func TestParseProcMounts(t *testing.T) {
	entries := parseProcMounts(procMountsFixture)
	if len(entries) != 6 {
		t.Fatalf("parsed %d entries, want 6: %+v", len(entries), entries)
	}
	if got := entries[2]; got.From != "/dev/nvme0n1p2" || got.On != "/" || got.Type != "ext4" {
		t.Errorf("root entry = %+v", got)
	}
	if got := entries[4]; got.From != "127.0.0.1:/Survey Data" || got.On != "/home/x/Volumes/Survey Data" {
		t.Errorf("escaped entry = %+v, want the spaces unescaped", got)
	}
	if !isMounted(entries, "/home/x/Volumes/Survey Data") {
		t.Error("an unescaped mountpoint is not found by isMounted")
	}
}

func TestUnescapeMount(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/plain/path", "/plain/path"},
		{`/a\040b`, "/a b"},
		{`/a\011b`, "/a\tb"},
		{`/a\134b`, `/a\b`},
		// Not an escape: a lone backslash, and a run too short to hold
		// three octal digits, are kept as written rather than eaten.
		{`/a\b`, `/a\b`},
		{`/trailing\`, `/trailing\`},
		{`/bad\099x`, `/bad\099x`},
	} {
		if got := unescapeMount(tc.in); got != tc.want {
			t.Errorf("unescapeMount(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
