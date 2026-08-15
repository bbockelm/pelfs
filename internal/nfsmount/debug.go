package nfsmount

import (
	"fmt"
	"os"
	"sync/atomic"
)

// nfsDebug enables per-operation tracing of the NFS backend's data path.
// It is meant for diagnosing client-visible corruption (short reads, files
// that read back shorter than they were written) against a real kernel NFS
// client, where the traffic pattern — concurrent RPCs, readahead, write
// coalescing — cannot be reproduced from a test harness.
//
// Set PELFS_NFS_DEBUG=1 to enable.
var nfsDebug = os.Getenv("PELFS_NFS_DEBUG") == "1"

// nfsNoHandleCache disables the write-handle cache, restoring the original
// open-write-close-per-RPC behavior. That refragments writes into one small
// object per RPC, but it is the switch for bisecting client-visible
// corruption: if a workload misbehaves with the cache on and behaves with
// PELFS_NFS_NO_HANDLE_CACHE=1, the cache is implicated; if it misbehaves
// either way, the cause is elsewhere.
var nfsNoHandleCache = os.Getenv("PELFS_NFS_NO_HANDLE_CACHE") == "1"

var nfsDebugSeq atomic.Uint64

func nfsDebugf(format string, args ...interface{}) {
	if !nfsDebug {
		return
	}
	fmt.Fprintf(os.Stderr, "pelfs-nfs[%d]: "+format+"\n",
		append([]interface{}{nfsDebugSeq.Add(1)}, args...)...)
}
