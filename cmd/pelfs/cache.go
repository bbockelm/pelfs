package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/control"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/ui"
)

// `pelfs cache` is the answer to "what is pelfs doing to my disk".
//
// Everything under the state directory's gencache is a CACHE in the strict
// sense — decoded chunks, spilled catalogs, pack trailers and whole packs
// are all re-derivable from the federation — so the two questions worth
// asking about it are how big it is and how to make it not be. A mount
// holds it to a budget on its own (genfs/gencache.go); this is for the
// user who wants to look, and for the user who wants the space back now.

// cmdCache reports or empties the local cache of one volume.
func cmdCache(args []string) int {
	clear := false
	if len(args) > 0 && args[0] == "clear" {
		clear, args = true, args[1:]
	}
	o, pos, err := parseArgs("cache", args, 0, 1, nil)
	if err != nil {
		return exitErr(err)
	}
	dir, err := cacheStateDir(o, pos)
	if err != nil {
		return exitErr(err)
	}
	cacheDir := filepath.Join(dir, "gencache")

	if !clear {
		usage, err := genfs.InspectCache(cacheDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("%s\n  no cache yet\n", cacheDir)
				return 0
			}
			return exitErr(err)
		}
		printCache(cacheDir, usage)
		return 0
	}

	// A live mount has catalogs open by path out of this directory, and
	// unlinking those from under SQLite is the one way a user could turn
	// their own cache into an I/O error. The mount's own budget is the
	// right tool while it is running.
	if live, how := mountIsLive(dir); live {
		return exitErr(fmt.Errorf("a mount is using %s (%s); unmount it first — "+
			"a running mount holds catalogs open out of this cache, and it bounds the cache itself while it runs", dir, how))
	}
	usage, err := genfs.ClearCache(cacheDir)
	if err != nil {
		return exitErr(err)
	}
	ui.Info("cleared {bytes} of local cache in {files} files from {dir}",
		"bytes", ui.ByteCount(usage.Bytes), "files", usage.Files, "dir", cacheDir)
	return 0
}

// cacheStateDir resolves which state directory the command is about:
// --state-dir if given, else the per-prefix directory of the positional
// argument. One of the two is required — guessing would be guessing which
// volume's cache to delete.
func cacheStateDir(o *cmdOpts, pos []string) (string, error) {
	if o.stateDir != "" {
		return o.stateDir, nil
	}
	if len(pos) == 1 {
		return volDir(pos[0]), nil
	}
	return "", errors.New("name the volume (pelfs cache <prefix>) or its state directory (--state-dir)")
}

// mountIsLive reports whether a session is really using this state
// directory. The socket FILE is not the test — a killed session leaves one
// behind, and refusing to clear a cache because of a dead mount's litter
// would send the user hunting for a process that does not exist. Dialling
// it is the test, and it is the same probe the control listener uses to
// decide whether a socket it found is a leftover.
func mountIsLive(dir string) (bool, string) {
	path := filepath.Join(dir, control.SocketName)
	if _, err := os.Stat(path); err != nil {
		return false, ""
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return false, ""
	}
	c.Close() //nolint:errcheck
	return true, "its control socket answers at " + path
}

func printCache(dir string, u genfs.CacheUsage) {
	fmt.Printf("%s\n", dir)
	for _, d := range u.Dirs {
		fmt.Printf("  %-9s %10s  %d files\n", d.Name, ui.ByteCount(d.Bytes), d.Files)
	}
	fmt.Printf("  %-9s %10s  %d files\n", "total", ui.ByteCount(u.Bytes), u.Files)
	fmt.Printf("\nEverything here is re-derivable from the federation; `pelfs cache clear` frees it.\n")
}

// parseCacheSize reads a byte budget written the way people write one:
// a plain number of bytes, or a number with a K/M/G/T suffix (binary,
// because that is what a cache budget is measured in and "4G" meaning
// 4,000,000,000 would be a surprise nobody wants from a disk quota).
func parseCacheSize(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	// "4Gi" and "4G" are the same number here, so the binary marker comes
	// off before the unit is read.
	num := strings.TrimSuffix(strings.TrimSuffix(v, "i"), "I")
	if num == "" {
		return 0, fmt.Errorf("--cache-size %q: want a byte count, optionally with a K/M/G/T suffix", v)
	}
	mult := int64(1)
	switch num[len(num)-1] {
	case 'k', 'K':
		mult = 1 << 10
	case 'm', 'M':
		mult = 1 << 20
	case 'g', 'G':
		mult = 1 << 30
	case 't', 'T':
		mult = 1 << 40
	}
	if mult > 1 {
		num = num[:len(num)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("--cache-size %q: want a byte count, optionally with a K/M/G/T suffix", v)
	}
	if n < 0 {
		return 0, fmt.Errorf("--cache-size %q: a cache cannot be smaller than nothing", v)
	}
	return n * mult, nil
}

// cacheBudget is the byte cap a mount holds its local cache to, or 0 for
// the default (genfs.DefaultCacheBytes).
func (o *cmdOpts) cacheBudget() (int64, error) { return parseCacheSize(o.cacheSize) }
