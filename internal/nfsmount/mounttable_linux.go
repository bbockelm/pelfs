//go:build linux

package nfsmount

import (
	"fmt"
	"os"
	"strings"
)

// procMounts is the kernel's mount table on Linux. /proc/self/mounts
// rather than /etc/mtab (a symlink to it on a modern system, a stale file
// on an old one) and rather than /proc/self/mountinfo (richer, and none of
// what it adds is wanted here).
const procMounts = "/proc/self/mounts"

// Entries reads the kernel's mount table.
func Entries() ([]Entry, error) {
	data, err := os.ReadFile(procMounts)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", procMounts, err)
	}
	return parseProcMounts(string(data)), nil
}

// parseProcMounts turns the file's contents into entries. Split out so the
// escaping rule below can be tested against a captured table.
func parseProcMounts(s string) []Entry {
	var out []Entry
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		out = append(out, Entry{
			From: unescapeMount(fields[0]),
			On:   unescapeMount(fields[1]),
			Type: fields[2],
		})
	}
	return out
}

// unescapeMount undoes the octal escaping the kernel applies to the
// characters that would otherwise break the field split: space, tab,
// newline and backslash are written \040 \011 \012 \134. A mount point
// with a space in its name is exactly the sort of path a Finder-facing
// volume has ("My Data"), so this is not decoration.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		var v byte
		ok := true
		for _, c := range []byte(s[i+1 : i+4]) {
			if c < '0' || c > '7' {
				ok = false
				break
			}
			v = v*8 + (c - '0')
		}
		if !ok {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(v)
		i += 3
	}
	return b.String()
}
