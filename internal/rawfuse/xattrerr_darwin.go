package rawfuse

import (
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// errNoXattr is the "no such xattr" status: ENOATTR on darwin (macFUSE
// convention; ENODATA is a distinct errno here).
const errNoXattr = fuse.Status(syscall.ENOATTR)
