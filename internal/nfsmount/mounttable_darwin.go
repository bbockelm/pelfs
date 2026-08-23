//go:build darwin

package nfsmount

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

// Entries reads the kernel's mount table.
//
// getfsstat(2) with MNT_NOWAIT, deliberately: the WAIT form asks every
// mounted filesystem to refresh its statistics first, which for an NFS
// mount means an FSSTAT RPC — and the server it would be sent to is THIS
// process. A poll that calls back into the thing it is polling is a
// deadlock waiting for a slow moment; NOWAIT reads the kernel's cached
// rows, and the fields this file wants (what is mounted where) are not
// statistics and are never stale.
//
// For the same reason this is not statfs(2) on the mount point, which is
// the obvious way to ask "is this still a mount": that call goes to the
// filesystem, so on our own NFS mount it is an RPC into ourselves, and on
// a mount that has just been ejected it is a call into a client that may
// still be tearing down.
func Entries() ([]Entry, error) {
	// Two calls rather than a grown buffer: the first, with a nil buffer,
	// returns the count, and asking for a few more rows than that absorbs
	// a mount appearing in between. A short read is not an error — it is
	// what the kernel does when the buffer is smaller than the table — so
	// the count returned, not the buffer's length, bounds the loop.
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, fmt.Errorf("getfsstat: %w", err)
	}
	buf := make([]unix.Statfs_t, n+8)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil, fmt.Errorf("getfsstat: %w", err)
	}
	out := make([]Entry, 0, n)
	for _, st := range buf[:n] {
		out = append(out, Entry{
			From: cstring(st.Mntfromname[:]),
			On:   cstring(st.Mntonname[:]),
			Type: cstring(st.Fstypename[:]),
		})
	}
	return out, nil
}

// cstring is the NUL-terminated fixed-width field the struct carries,
// as a Go string.
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
