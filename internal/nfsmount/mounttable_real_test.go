//go:build darwin || linux

package nfsmount

import "testing"

// The real mount table, read the platform's way. It asserts only what is
// true of every machine this can run on -- "/" is a mount point and a path
// that cannot exist is not -- which is enough to catch the failures that
// matter: a struct layout that decodes to garbage, and a syscall wrapper
// that returns nothing at all.
//
// Nothing here mounts anything. On macOS this is getfsstat(2) with
// MNT_NOWAIT, which reads the kernel's cached rows and sends no RPC to any
// filesystem, ours included.
func TestEntriesReadsTheRealMountTable(t *testing.T) {
	entries, err := Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the mount table came back empty")
	}
	if !isMounted(entries, "/") {
		t.Errorf("/ is not in the mount table: %+v", entries)
	}
	for _, e := range entries {
		if e.On == "" || e.Type == "" {
			t.Errorf("entry decoded with empty fields: %+v", e)
		}
	}
	if mounted, err := Mounted("/"); err != nil || !mounted {
		t.Errorf("Mounted(/) = %v, %v; want true, nil", mounted, err)
	}
	if mounted, err := Mounted("/pelfs-no-such-mountpoint-9c1f"); err != nil || mounted {
		t.Errorf("Mounted(absent) = %v, %v; want false, nil", mounted, err)
	}
}
