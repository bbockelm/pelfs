package nfsmount

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Tracing the NFS backend's data path is how client-visible corruption gets
// diagnosed: short reads, false EOFs, files that read back shorter than
// they were written. The traffic pattern that provokes it — a real kernel
// client's concurrent RPCs, readahead and write coalescing — cannot be
// reproduced from a test harness, so the switches are environment
// variables that can be flipped on a real mount:
//
//	PELFS_NFS_DEBUG=1              trace to stderr
//	PELFS_NFS_DEBUG=/tmp/foo.txt   trace to a file (created/truncated)
//	PELFS_NFS_NO_HANDLE_CACHE=1    disable the write-handle cache
//
// The file form is the useful one for a long run: stderr is interleaved
// with the subshell's own output, and the trace is far too chatty to read
// past.
var (
	nfsDebug   bool
	nfsDebugMu sync.Mutex
	nfsDebugW  *os.File
)

// nfsNoHandleCache disables the write-handle cache, restoring the original
// open-write-close-per-RPC behavior. That refragments writes into one small
// object per RPC, but it is the switch for bisecting client-visible
// corruption: if a workload misbehaves with the cache on and behaves with
// PELFS_NFS_NO_HANDLE_CACHE=1, the cache is implicated; if it misbehaves
// either way, the cause is elsewhere.
var nfsNoHandleCache = os.Getenv("PELFS_NFS_NO_HANDLE_CACHE") == "1"

var nfsDebugSeq atomic.Uint64

func init() {
	v := os.Getenv("PELFS_NFS_DEBUG")
	switch {
	case v == "":
		return
	case v == "1" || v == "true":
		nfsDebug, nfsDebugW = true, os.Stderr
	default:
		f, err := os.Create(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: cannot open NFS debug log %s: %v\n", v, err)
			nfsDebug, nfsDebugW = true, os.Stderr
			return
		}
		nfsDebug, nfsDebugW = true, f
		fmt.Fprintf(os.Stderr, "pelfs: NFS debug trace -> %s\n", v)
	}
}

func nfsDebugf(format string, args ...interface{}) {
	if !nfsDebug {
		return
	}
	line := fmt.Sprintf("pelfs-nfs[%d] %s: "+format+"\n",
		append([]interface{}{nfsDebugSeq.Add(1), time.Now().Format("15:04:05.000")}, args...)...)
	nfsDebugMu.Lock()
	_, _ = nfsDebugW.WriteString(line)
	nfsDebugMu.Unlock()
}
