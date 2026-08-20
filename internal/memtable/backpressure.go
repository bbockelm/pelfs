package memtable

import (
	"sync/atomic"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
)

// Saying that the write path is applying backpressure.
//
// The ring refusing an append IS the backpressure rule (appendLocked), and
// it was entirely silent: the counter went up, and the counter was
// reachable only through Store.Stats, which one caller read one field of.
// From outside the process a mount pacing its writes against a 2 MiB/s
// uplink and a mount that has hung look identical — the same unmoving
// terminal, the same unfinished copy — and only this layer knows which one
// it is.
//
// So it says so, once, and then at most once a minute. A blocked write is
// never one write: the ring stays full for as long as the uplink is behind,
// so every writer that arrives blocks too, and a line per occurrence would
// bury the terminal in exactly the situation where the user most needs to
// read it. Suppressed occurrences are counted and carried by the next line
// that gets through, which keeps "this is happening in bulk" visible
// without being expensive — the same shape, and the same reasoning, as the
// EIO explainer in internal/rawfuse.

// blockedReportEvery bounds how often the backpressure notice speaks.
// A minute: long enough that a sustained stall is one line rather than
// thousands, short enough that a user watching a copy get slower learns
// why while they are still watching.
const blockedReportEvery = time.Minute

var (
	blockedSuppressed atomic.Int64
	blockedReportedAt atomic.Int64 // unix nanos; zero reports the first one
)

// reportBlockedWrite says that a write is waiting on the packer, with how
// far behind the uplink is. Callers hold the store lock; nothing here
// blocks on anything but the queue's own mutex.
func reportBlockedWrite(backlog int64) {
	now := time.Now().UnixNano()
	last := blockedReportedAt.Load()
	if now-last < int64(blockedReportEvery) || !blockedReportedAt.CompareAndSwap(last, now) {
		blockedSuppressed.Add(1)
		return
	}
	// The remedy is named because there is one, and because the first
	// instinct — kill it and start again — is the wrong one: the bytes
	// already written are safe in the overlay and are going out.
	if n := blockedSuppressed.Swap(0); n > 0 {
		ui.Warn("uploads are behind; writes are pacing against the uplink "+
			"({backlog} cut and not yet sent, {waits} other writes waited since the last notice). "+
			"Nothing is lost — the session keeps writing as fast as the uplink drains",
			"backlog", ui.ByteCount(backlog), "waits", n)
		return
	}
	ui.Warn("uploads are behind; writes are pacing against the uplink "+
		"({backlog} cut and not yet sent). "+
		"Nothing is lost — the session keeps writing as fast as the uplink drains",
		"backlog", ui.ByteCount(backlog))
}
