package importvol

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// A CHECKPOINT, BECAUSE AN IMPORT OF A LARGE VOLUME IS HOURS. Copying
// every byte of a source once is the same wall clock a graft's spider
// pays, and `pelfs graft` has had a checkpoint since it landed for
// exactly that reason: an operation that cannot survive a Ctrl-C, an
// eviction or a token expiring is not usable at that size.
//
// # What makes resuming safe rather than merely convenient
//
// A pack is UPLOADED before it is recorded here, and the source packs it
// consumed are recorded only after it. So a name in this file is a name
// that already exists at the far end, and the resume proves it by
// fetching the trailer and checking it against the hash recorded beside
// the name. Nothing is trusted because it was written down.
//
// A pack that has since been collected is not an error either. Everything
// an interrupted import uploaded is unreferenced — no superblock names it
// — so retention is entitled to take it once it ages past the volume's
// grace window. The resume simply copies those identities again.
//
// # What it is keyed on, and why re-keying discards it
//
// The header names the exact source generation, the destination path and
// the pack cut. Change any of them and the work already done is work for
// a different import: a different generation wants different bytes, a
// different path is a different tree, and a different cut would leave the
// volume holding two differently-sized halves of one copy. A header
// mismatch therefore discards rather than adapts, and says which field
// moved.
const checkpointVersion = "pelfs-import-checkpoint v1"

// Header identifies the import a checkpoint belongs to.
type Header struct {
	SourceVolumeID   [16]byte
	SourceGeneration uint64
	SourceHash       [32]byte
	Path             string
	TargetPackSize   int64
}

func (h Header) line() string {
	return fmt.Sprintf("%s %x %d %x %d %s", checkpointVersion, h.SourceVolumeID[:],
		h.SourceGeneration, h.SourceHash[:], h.TargetPackSize, h.Path)
}

// differs names the first field that moved, for a message that says what
// to do rather than that something is wrong.
func (h Header) differs(other Header) string {
	switch {
	case h.SourceVolumeID != other.SourceVolumeID:
		return fmt.Sprintf("it was taken against source volume %x, not %x",
			other.SourceVolumeID[:8], h.SourceVolumeID[:8])
	case h.SourceHash != other.SourceHash:
		return fmt.Sprintf("the source has sealed since: it was taken against generation %d, "+
			"and this import is of generation %d", other.SourceGeneration, h.SourceGeneration)
	case h.Path != other.Path:
		return fmt.Sprintf("it was taken for %s, not %s", other.Path, h.Path)
	case h.TargetPackSize != other.TargetPackSize:
		return fmt.Sprintf("it cut packs at %d bytes and this run cuts at %d",
			other.TargetPackSize, h.TargetPackSize)
	}
	return ""
}

// Checkpoint is the append-only record of one import's copy.
type Checkpoint struct {
	path string
	f    *os.File
	hdr  Header
	// discarded says why a previous checkpoint was thrown away, for the
	// caller to report. Empty when one was resumed or none existed.
	discarded string
}

// CheckpointPath is where an import's checkpoint lives: one per
// (destination path, source), under the state directory, named by a hash
// so that a path with slashes in it is a filename.
func CheckpointPath(stateDir, dstPath, source string) string {
	sum := blake(dstPath + "\x00" + source)
	return filepath.Join(stateDir, "import", "ckpt-"+sum[:16]+".txt")
}

// OpenCheckpoint opens or creates the checkpoint for one import. A file
// whose header does not match this import is DISCARDED and the reason
// reported — see the type comment for why adapting one would be worse.
func OpenCheckpoint(path string, hdr Header) (*Checkpoint, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	c := &Checkpoint{path: path, hdr: hdr}
	existing, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Nothing to resume.
	case err != nil:
		return nil, err
	default:
		if why := c.headerMismatch(existing); why != "" {
			c.discarded = why
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	c.f = f
	if fi, err := f.Stat(); err == nil && fi.Size() == 0 {
		if _, err := fmt.Fprintln(f, hdr.line()); err != nil {
			return nil, err
		}
		if err := f.Sync(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Discarded reports why a previous checkpoint was thrown away, empty when
// none was.
func (c *Checkpoint) Discarded() string { return c.discarded }

// Path is the file, for a caller that wants to name it in a report.
func (c *Checkpoint) Path() string { return c.path }

func (c *Checkpoint) headerMismatch(body []byte) string {
	line, _, _ := strings.Cut(string(body), "\n")
	if !strings.HasPrefix(line, checkpointVersion+" ") {
		return "it was written by a different version of this tool"
	}
	got, err := parseHeader(line)
	if err != nil {
		return "it is unreadable: " + err.Error()
	}
	return c.hdr.differs(got)
}

func parseHeader(line string) (Header, error) {
	// "pelfs-import-checkpoint v1 <volid> <gen> <hash> <target> <path...>"
	fields := strings.SplitN(line, " ", 7)
	if len(fields) < 7 {
		return Header{}, fmt.Errorf("header has %d fields", len(fields))
	}
	var h Header
	vol, err := hex.DecodeString(fields[2])
	if err != nil || len(vol) != 16 {
		return h, fmt.Errorf("volume id %q", fields[2])
	}
	copy(h.SourceVolumeID[:], vol)
	if h.SourceGeneration, err = strconv.ParseUint(fields[3], 10, 64); err != nil {
		return h, fmt.Errorf("generation %q", fields[3])
	}
	sum, err := hex.DecodeString(fields[4])
	if err != nil || len(sum) != 32 {
		return h, fmt.Errorf("source hash %q", fields[4])
	}
	copy(h.SourceHash[:], sum)
	if h.TargetPackSize, err = strconv.ParseInt(fields[5], 10, 64); err != nil {
		return h, fmt.Errorf("target pack size %q", fields[5])
	}
	h.Path = strings.TrimRight(fields[6], "\n")
	return h, nil
}

// notePack records a pack this import uploaded. It is fsync'd before the
// call returns, because the whole value of the record is that a crash one
// instruction later still finds it.
func (c *Checkpoint) notePack(sp packstore.SealedPack) error {
	if _, err := fmt.Fprintf(c.f, "dst %s %d %x\n", sp.Name, sp.Size, sp.TrailerHash[:]); err != nil {
		return err
	}
	return c.f.Sync()
}

// noteSource records a source pack fully consumed into packs already
// uploaded.
func (c *Checkpoint) noteSource(name string) error {
	if _, err := fmt.Fprintf(c.f, "src %s\n", name); err != nil {
		return err
	}
	return c.f.Sync()
}

// Read is what a previous run left: the packs it uploaded and the source
// packs it finished with.
func (c *Checkpoint) Read() ([]packstore.SealedPack, []string, error) {
	f, err := os.Open(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer f.Close() //nolint:errcheck
	var packs []packstore.SealedPack
	var srcDone []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "dst":
			if len(fields) != 4 {
				continue
			}
			size, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				continue
			}
			sum, err := hex.DecodeString(fields[3])
			if err != nil || len(sum) != 32 {
				continue
			}
			sp := packstore.SealedPack{Name: fields[1], Size: size}
			copy(sp.TrailerHash[:], sum)
			packs = append(packs, sp)
		case "src":
			if len(fields) == 2 {
				srcDone = append(srcDone, fields[1])
			}
		}
	}
	return packs, srcDone, sc.Err()
}

// Close flushes and closes the file. Remove is separate because a
// successful import removes the checkpoint and a failed one keeps it.
func (c *Checkpoint) Close() error {
	if c.f == nil {
		return nil
	}
	err := c.f.Close()
	c.f = nil
	return err
}

// Remove drops the checkpoint, which is what a completed import does: the
// packs it names are now referenced by a signed generation and resuming
// into them would be resuming an import that is over.
func (c *Checkpoint) Remove() error {
	if err := c.Close(); err != nil {
		return err
	}
	if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// blake is the short hash naming a checkpoint file.
func blake(s string) string {
	sum := superblock.Hash([]byte(s))
	return hex.EncodeToString(sum[:])
}
