//go:build !darwin && !windows

package rawfuse

import "github.com/hanwen/go-fuse/v2/fuse"

// errNoXattr is the "no such xattr" status: ENODATA (== ENOATTR on Linux).
const errNoXattr = fuse.ENODATA
