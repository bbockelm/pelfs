//go:build !darwin && !linux

package nfsmount

import "testing"

// On a platform with no mount-table reader, "unknown" is the answer and an
// empty table is not. The distinction is the whole contract of
// mounttable_other.go, and it is load-bearing three times over: Mounted
// would report a real mount point as absent, WatchUnmount would fire the
// instant it started (a session sealing itself and exiting for no reason),
// and Unmount's "already gone" shortcut would skip a teardown that was
// needed. Every caller reads an error as "still mounted", so an error is
// what this must return.
func TestEntriesReportsUnknownRatherThanEmpty(t *testing.T) {
	entries, err := Entries()
	if err == nil {
		t.Fatalf("Entries on a platform with no reader returned %d entries and no error; "+
			"an empty table is a positive claim that nothing is mounted anywhere", len(entries))
	}
	if entries != nil {
		t.Errorf("Entries returned %v alongside its error, want nil", entries)
	}
	// Mounted must propagate the error rather than flattening it to false:
	// isMounted over an empty slice is false, and returning that would be
	// the same lie one layer up.
	if mounted, err := Mounted("/"); err == nil {
		t.Errorf("Mounted(/) = %v with no error; the answer is not known here", mounted)
	}
}
