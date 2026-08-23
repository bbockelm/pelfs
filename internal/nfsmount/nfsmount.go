package nfsmount

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"

	"github.com/bbockelm/pelfs/internal/ui"
)

// handleCacheSize bounds the file-handle <-> path cache in the NFS handler.
// Handles evicted from the cache force clients to re-lookup, so keep it
// comfortably above the number of files a workload touches concurrently.
const handleCacheSize = 1 << 20

// Server is a running loopback NFSv3 server for one filesystem.
type Server struct {
	Port     int
	ln       net.Listener
	serveErr chan error
}

// quietLogger routes go-nfs's own log lines into pelfs's.
//
// go-nfs logs through the standard library's log package, which writes to
// raw stderr in its own format and is therefore absent from a structured
// pelfs log entirely — and the few lines that name a failing RPC ("Error
// applying attributes", the one upstream line that explains an EIO on
// CREATE) are exactly the lines somebody reading that log is looking for.
// A message the server emits about our filesystem is a pelfs message.
type quietLogger struct {
	nfs.Logger
}

func (l *quietLogger) Errorf(format string, args ...interface{}) {
	ui.Error("nfs server: {message}", "message", strings.TrimSpace(fmt.Sprintf(format, args...)))
}

func (l *quietLogger) Error(args ...interface{}) {
	ui.Error("nfs server: {message}", "message", strings.TrimSpace(fmt.Sprint(args...)))
}

func (l *quietLogger) Warnf(format string, args ...interface{}) {
	ui.Warn("nfs server: {message}", "message", strings.TrimSpace(fmt.Sprintf(format, args...)))
}

func (l *quietLogger) Warn(args ...interface{}) {
	ui.Warn("nfs server: {message}", "message", strings.TrimSpace(fmt.Sprint(args...)))
}

func init() {
	nfs.SetLogger(&quietLogger{Logger: nfs.Log})
}

// ServeOptions is how one server differs from the default.
type ServeOptions struct {
	// HideFinderFiles makes the served filesystem refuse the Finder's
	// bookkeeping files (finderfiles.go). It belongs to a mount the Finder
	// can SEE, which is why it is not the default: an invisible volume is
	// never asked for a .DS_Store, and a Linux client never asks either.
	HideFinderFiles bool
}

// Serve starts an NFSv3 server for bfs on a random 127.0.0.1 port.
func Serve(bfs billy.Filesystem, opts ServeOptions) (*Server, error) {
	// IPv4 explicitly: mount_nfs is pointed at 127.0.0.1, and a hostname
	// like "localhost" can resolve to ::1 where nothing listens.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("nfs listen: %w", err)
	}
	// diagnose sits between go-nfs and the filesystem so that an error
	// go-nfs will flatten to NFS3ERR_IO is reported before it is lost
	// (diag.go).
	var hide func(string) bool
	if opts.HideFinderFiles {
		hide = finderDropping
	}
	handler := nfshelper.NewNullAuthHandler(diagnose(bfs, hide))
	cached := newHandles(handler, handleCacheSize)
	s := &Server{
		Port:     ln.Addr().(*net.TCPAddr).Port,
		ln:       ln,
		serveErr: make(chan error, 1),
	}
	go func() {
		s.serveErr <- nfs.Serve(ln, cached)
	}()
	return s, nil
}

// Close stops the NFS server. Unmount first.
func (s *Server) Close() error {
	return s.ln.Close()
}

// MountOptions is how one mount differs from the default. The zero value
// is the mount pelfs has always made: hidden from the Finder, exported as
// "/", which is what every scripted and CI use of this backend relies on.
type MountOptions struct {
	// VolumeName, when set, is exported as "/<VolumeName>" instead of "/".
	//
	// It is a LABEL and nothing else: the handler answers MOUNT for any
	// directory path with the same filesystem (go-nfs's NullAuthHandler
	// ignores the request's dirpath), so the export path is free for us to
	// choose. It is worth choosing because it is one of the two places a
	// name for this volume can come from — the other being the last
	// component of the mount point — and which of the two macOS shows for
	// an NFS volume is not something a mount option can settle: mount_nfs
	// has no `volname` (its manual page lists every option it takes, and
	// there is none), so the name is whatever the client synthesizes.
	// Setting both makes the answer the same either way.
	VolumeName string
	// Browsable drops the nobrowse mount option, which is what keeps a
	// mount out of the macOS GUI (mount(8): "the mount point should not be
	// visible via the GUI"). A browsable volume appears in the Finder
	// sidebar under Locations, with an eject button — which is the whole
	// point, and also the reason a session that sets this must watch the
	// mount table (mounttable.go): eject detaches the mount and tells the
	// server nothing.
	Browsable bool
}

// Mount attaches the served filesystem at mountPoint using the OS NFS
// client. On macOS this works unprivileged; note the first access from an
// app may trigger the one-time "access files on a network volume"
// permission prompt (TCC).
func (s *Server) Mount(mountPoint string, opts MountOptions) error {
	// Fail fast if the server already died (e.g. port grabbed).
	select {
	case err := <-s.serveErr:
		return fmt.Errorf("nfs server exited: %v", err)
	default:
	}
	name, args := mountCommand(runtime.GOOS, s.Port, mountPoint, opts)
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// mountCommand builds the client invocation. It is a pure function of the
// platform, the port and the options so that the argument list -- the one
// thing about this backend that cannot be exercised without mounting
// something -- can be asserted on both platforms.
//
// The client command differs by platform: macOS ships mount_nfs and
// accepts its own option spellings, Linux mounts through mount(8) with
// -t nfs. Keeping both here means Linux CI can exercise the NFS frontend
// even though its reason for existing is macOS without macFUSE.
func mountCommand(goos string, port int, mountPoint string, opts MountOptions) (string, []string) {
	export := "127.0.0.1:/" + opts.VolumeName
	if goos == "linux" {
		linuxOpts := []string{
			"nolock", "vers=3", "tcp",
			fmt.Sprintf("port=%d", port),
			fmt.Sprintf("mountport=%d", port),
			"noresvport", "soft", "retrans=3", "actimeo=1",
		}
		return "mount", []string{"-t", "nfs", "-o", strings.Join(linuxOpts, ","), export, mountPoint}
	}
	o := []string{
		"nolocks", // no NLM; local single-client mount
		"vers=3",
		"tcp",
		fmt.Sprintf("port=%d", port),
		fmt.Sprintf("mountport=%d", port),
		"noresvport", // unprivileged client source port
		"soft",       // fail I/O rather than wedge if our server dies
		"retrans=3",
		"actimeo=1", // we are the only writer; keep attr caching short
	}
	if !opts.Browsable {
		o = append(o, "nobrowse") // keep the volume out of the GUI
	}
	return "mount_nfs", []string{"-o", strings.Join(o, ","), export, mountPoint}
}

// Unmount detaches the filesystem, escalating to forced unmount after a few
// polite attempts.
//
// A path that is no longer a mount point is success, not failure. Two
// ordinary paths reach here that way: a Finder eject (or any outside
// `umount`) has already detached the mount and the session is only now
// running down, and the escalation below succeeded on an attempt whose
// exit status the shell reported as an error. Without this, the first case
// spends three seconds failing six commands and then reports the last
// one's message as the session's unmount error -- which is how a clean
// teardown came to be recorded as a failed one.
func Unmount(mountPoint string) error {
	if mounted, err := Mounted(mountPoint); err == nil && !mounted {
		return nil
	}
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		var cmds [][]string
		if attempt < 3 {
			cmds = [][]string{{"umount", mountPoint}}
		} else if runtime.GOOS == "linux" {
			cmds = [][]string{{"umount", "-f", mountPoint}, {"umount", "-l", mountPoint}}
		} else {
			cmds = [][]string{{"umount", "-f", mountPoint}, {"diskutil", "unmount", "force", mountPoint}}
		}
		for _, c := range cmds {
			out, err := exec.Command(c[0], c[1:]...).CombinedOutput()
			if err == nil {
				return nil
			}
			lastErr = fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
		// The command failed but the mount may still be gone: a forced
		// unmount that detached the filesystem and then complained, or an
		// eject that landed between attempts. What the caller asked for is
		// the state, not the exit status.
		if mounted, err := Mounted(mountPoint); err == nil && !mounted {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return lastErr
}

func randomSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", os.Getpid())
	}
	return hex.EncodeToString(b[:])
}
