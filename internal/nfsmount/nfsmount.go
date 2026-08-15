package nfsmount

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"
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

// quietLogger drops go-nfs log lines that are expected and harmless here,
// so that real problems stay visible.
type quietLogger struct {
	nfs.Logger
}

// Errorf filters the EXCLUSIVE-create rejection. go-nfs does not implement
// NFSv3 EXCLUSIVE mode, which is what every O_CREAT|O_EXCL open becomes —
// git alone does it for each lockfile and every mkstemp, so the message
// repeats constantly. The client falls back to GUARDED, which preserves the
// property that matters (the create still fails if the name already
// exists); only retransmission idempotency is lost, and a loopback TCP
// mount does not retransmit.
func (l *quietLogger) Errorf(format string, args ...interface{}) {
	if strings.Contains(format, "exclusive") {
		return
	}
	l.Logger.Errorf(format, args...)
}

func init() {
	nfs.SetLogger(&quietLogger{Logger: nfs.Log})
}

// Serve starts an NFSv3 server for bfs on a random 127.0.0.1 port.
func Serve(bfs billy.Filesystem) (*Server, error) {
	// IPv4 explicitly: mount_nfs is pointed at 127.0.0.1, and a hostname
	// like "localhost" can resolve to ::1 where nothing listens.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("nfs listen: %w", err)
	}
	handler := nfshelper.NewNullAuthHandler(bfs)
	cached := nfshelper.NewCachingHandler(handler, handleCacheSize)
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

// Mount attaches the served filesystem at mountPoint using the OS NFS
// client. On macOS this works unprivileged; note the first access from an
// app may trigger the one-time "access files on a network volume"
// permission prompt (TCC).
func (s *Server) Mount(mountPoint, volumeName string) error {
	// Fail fast if the server already died (e.g. port grabbed).
	select {
	case err := <-s.serveErr:
		return fmt.Errorf("nfs server exited: %v", err)
	default:
	}
	opts := []string{
		"nolocks", // no NLM; local single-client mount
		"vers=3",
		"tcp",
		fmt.Sprintf("port=%d", s.Port),
		fmt.Sprintf("mountport=%d", s.Port),
		"noresvport", // unprivileged client source port
		"soft",       // fail I/O rather than wedge if our server dies
		"retrans=3",
		"actimeo=1", // we are the only writer; keep attr caching short
		"nobrowse",  // keep Finder from indexing the volume
	}
	out, err := exec.Command("mount_nfs",
		"-o", strings.Join(opts, ","),
		"127.0.0.1:/", mountPoint).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount_nfs: %v: %s", err, strings.TrimSpace(string(out)))
	}
	_ = volumeName // reserved: could set via -o with future macOS support
	return nil
}

// Unmount detaches the filesystem, escalating to forced unmount after a few
// polite attempts.
func Unmount(mountPoint string) error {
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		var cmds [][]string
		if attempt < 3 {
			cmds = [][]string{{"umount", mountPoint}}
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
