package graft

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// Resumability, which at TB scale is not a nicety.
//
// A graft reads every byte of the source once. At 10 TB and a plausible
// 500 MB/s that is six hours, and six hours is longer than a token, a
// spot instance, a laptop lid or a person's patience. A walk that had to
// start again from zero because of any of those would not be a feature
// anyone could use, so the walk writes down what it has hashed as it goes
// and a re-run pays only for what changed.
//
// # What is durable, and what a crash costs
//
// An append-only log of COMPLETED OBJECTS, next to the volume's state.
// One record per source object, written only once every block of that
// object has been hashed and the object's delivered length has been
// checked against its listed length. A half-hashed object leaves no
// record and is redone; nothing partial is ever resumed, which is what
// keeps the resume logic to a comparison rather than a reconciliation.
//
// Each record is flushed with write(2) as it is made, so process death —
// Ctrl-C, OOM, a token expiring, an eviction — loses NOTHING. fsync runs
// on a timer instead of per record, so a machine crash loses at most the
// last few seconds of work; paying an fsync per object would dominate the
// walk of a tree of small files and buy protection against the one
// failure mode that is not what this exists for.
//
// A torn tail (the machine died mid-write) is discarded on load: records
// are length-prefixed and CRC'd, and the reader stops at the first one
// that does not check out. The log is append-only, so a discarded tail
// can never take good records with it.
//
// # How a resumed run proves it is resuming the same source
//
// Two gates, and neither of them costs a request.
//
// The HEADER records the source URL, the mount path, the block policy and
// the identity function. A run whose parameters differ from the log's is
// not a resume of it — a different block size moves every identity — so
// the log is discarded and said to be discarded, rather than half-used.
//
// Each RECORD carries the object's size and mtime as the listing reported
// them at the moment it was hashed. A resumed run re-lists the source,
// which it has to do anyway to know what to walk, and compares. An object
// whose size or mtime moved is re-hashed; an object that vanished is
// dropped; an object that appeared is hashed. So the resume costs one
// listing and no HEADs, and it detects everything a listing can see.
//
// What a listing cannot see is a rewrite that preserves size AND mtime.
// That is the same blind spot fsck's cheap mode has, it is stated rather
// than papered over, and the answer to it is the same as for any other
// staleness: the per-block identity check at READ time catches it, fails
// closed and names the object.
//
// # Why the log is KEPT on success
//
// Because it makes a refresh cost what changed rather than what exists. A
// second `pelfs graft` of the same source re-lists, finds every record
// still matching, hashes nothing, and republishes the same index — which
// is what `--refresh` has to be. Deleting the log at the end would make
// the cheapest useful operation the most expensive one.

const (
	ckptMagic   = "PELFSGCK"
	ckptVersion = 1
	// ckptSyncEvery bounds what a machine crash can cost.
	ckptSyncEvery = 5 * time.Second
)

// CheckpointHeader is the walk's identity: the parameters that must match
// for a log to be a resume of this run rather than of a different one.
type CheckpointHeader struct {
	Version   int    `json:"version"`
	Source    string `json:"source"`
	Mount     string `json:"mount"`
	Block     int64  `json:"block"`
	BlockMax  int64  `json:"block_max"`
	PerObject int    `json:"blocks_per_object"`
	Hasher    string `json:"hasher"`
	Created   string `json:"created"`
}

// sameWalk reports whether a log written under h can be resumed by a run
// that wants want. Created is deliberately excluded: it is provenance for
// a human, not part of the identity.
func (h CheckpointHeader) sameWalk(want CheckpointHeader) bool {
	return h.Version == want.Version && h.Source == want.Source && h.Mount == want.Mount &&
		h.Block == want.Block && h.BlockMax == want.BlockMax &&
		h.PerObject == want.PerObject && h.Hasher == want.Hasher
}

// CheckObject is one completed source object: what the listing said about
// it, how it was cut, and what each of its blocks hashed to.
//
// Body is the whole file for the small ones the spider keeps for inlining
// (InlineKeep). Keeping it here is what makes a resumed run of a tree of
// small files free rather than merely cheaper: without it every inlined
// file would be re-read to be re-inlined.
type CheckObject struct {
	Key     string
	Size    int64
	MtimeNS int64
	Block   int64
	IDs     []chunkid.Identity
	Body    []byte
}

// Checkpoint is the append-only log of completed objects.
type Checkpoint struct {
	path string

	mu       sync.Mutex
	f        *os.File
	w        *bufio.Writer
	lastSync time.Time
	done     map[string]*CheckObject
	resumed  int64 // bytes covered by records loaded from disk
	closed   bool
}

// CheckpointPath is where the log for one (volume state, mount, source)
// lives. It is derived rather than chosen so that a re-run finds its own
// log without the user having to name it.
func CheckpointPath(stateDir, mount, source string) string {
	h := chunkid.NewHasher(nil).Sum([]byte(mount + "\x00" + source))
	return spoolPath(stateDir, "ckpt-"+h.Hex()[:32]+".log")
}

// OpenCheckpoint loads any existing log for this walk and opens it for
// appending. A log written for a DIFFERENT walk is truncated and the
// reason is reported through discarded, so the caller can say so out loud
// rather than silently re-reading a terabyte.
func OpenCheckpoint(path string, want CheckpointHeader) (c *Checkpoint, discarded string, err error) {
	want.Version = ckptVersion
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, "", fmt.Errorf("graft: checkpoint: %w", err)
	}
	c = &Checkpoint{path: path, done: make(map[string]*CheckObject), lastSync: time.Now()}
	keep := int64(0)
	if raw, err := os.Open(path); err == nil {
		keep, discarded = c.replay(raw, want)
		raw.Close() //nolint:errcheck
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("graft: checkpoint: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("graft: checkpoint: %w", err)
	}
	if keep == 0 {
		// A fresh or discarded log: write the header first, so an
		// interrupted run leaves something a later one can identify.
		if err := f.Truncate(0); err != nil {
			f.Close() //nolint:errcheck
			return nil, "", err
		}
		want.Created = time.Now().UTC().Format(time.RFC3339)
		hdr, err := json.Marshal(want)
		if err != nil {
			f.Close() //nolint:errcheck
			return nil, "", err
		}
		head := make([]byte, 16+len(hdr))
		copy(head[0:8], ckptMagic)
		binary.LittleEndian.PutUint32(head[8:], ckptVersion)
		binary.LittleEndian.PutUint32(head[12:], uint32(len(hdr)))
		copy(head[16:], hdr)
		if _, err := f.WriteAt(head, 0); err != nil {
			f.Close() //nolint:errcheck
			return nil, "", err
		}
		keep = int64(len(head))
		c.done = make(map[string]*CheckObject)
		c.resumed = 0
	}
	// Append after the last GOOD record, which drops a torn tail.
	if err := f.Truncate(keep); err != nil {
		f.Close() //nolint:errcheck
		return nil, "", err
	}
	if _, err := f.Seek(keep, io.SeekStart); err != nil {
		f.Close() //nolint:errcheck
		return nil, "", err
	}
	c.f, c.w = f, bufio.NewWriterSize(f, 1<<20)
	return c, discarded, nil
}

// replay reads what is already on disk and reports how many bytes of it
// are good, plus why any of it was thrown away.
func (c *Checkpoint) replay(f *os.File, want CheckpointHeader) (keep int64, discarded string) {
	r := bufio.NewReaderSize(f, 1<<20)
	head := make([]byte, 16)
	if _, err := io.ReadFull(r, head); err != nil || string(head[0:8]) != ckptMagic {
		return 0, "the checkpoint is not one this build wrote"
	}
	if binary.LittleEndian.Uint32(head[8:]) != ckptVersion {
		return 0, "the checkpoint is an older format"
	}
	hlen := int(binary.LittleEndian.Uint32(head[12:]))
	if hlen < 0 || hlen > 1<<20 {
		return 0, "the checkpoint header is not a plausible length"
	}
	hbuf := make([]byte, hlen)
	if _, err := io.ReadFull(r, hbuf); err != nil {
		return 0, "the checkpoint header is truncated"
	}
	var got CheckpointHeader
	if err := json.Unmarshal(hbuf, &got); err != nil {
		return 0, "the checkpoint header does not parse"
	}
	if !got.sameWalk(want) {
		return 0, fmt.Sprintf("the checkpoint was written for %s at %s cut %d/%d/%d, not %s at %s cut %d/%d/%d",
			got.Source, got.Mount, got.Block, got.BlockMax, got.PerObject,
			want.Source, want.Mount, want.Block, want.BlockMax, want.PerObject)
	}
	keep = int64(16 + hlen)
	for {
		var lenbuf [8]byte
		if _, err := io.ReadFull(r, lenbuf[:]); err != nil {
			return keep, discarded // clean end, or a tail too short to be a record
		}
		n := binary.LittleEndian.Uint32(lenbuf[0:])
		sum := binary.LittleEndian.Uint32(lenbuf[4:])
		if n == 0 || n > 1<<30 {
			return keep, "the checkpoint's last record is torn and was dropped"
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return keep, "the checkpoint's last record is torn and was dropped"
		}
		if crc32.ChecksumIEEE(payload) != sum {
			return keep, "the checkpoint's last record failed its checksum and was dropped"
		}
		o, err := decodeCheckObject(payload)
		if err != nil {
			return keep, "the checkpoint's last record does not decode and was dropped"
		}
		if _, dup := c.done[o.Key]; !dup {
			c.resumed += o.Size
		}
		c.done[o.Key] = o
		keep += 8 + int64(n)
	}
}

// Done reports what the log already holds for one source object.
func (c *Checkpoint) Done(key string) (*CheckObject, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o, ok := c.done[key]
	return o, ok
}

// Resumed is how many source bytes the loaded records cover, before any
// of them has been checked against a fresh listing.
func (c *Checkpoint) Resumed() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resumed
}

// Forget drops a record whose object no longer matches the source, so a
// re-run does not think it is done.
func (c *Checkpoint) Forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if o, ok := c.done[key]; ok {
		c.resumed -= o.Size
		delete(c.done, key)
	}
}

// Record appends one completed object. Safe for concurrent callers.
func (c *Checkpoint) Record(o *CheckObject) error {
	payload := encodeCheckObject(o)
	var lenbuf [8]byte
	binary.LittleEndian.PutUint32(lenbuf[0:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(lenbuf[4:], crc32.ChecksumIEEE(payload))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("graft: checkpoint is closed")
	}
	if _, err := c.w.Write(lenbuf[:]); err != nil {
		return err
	}
	if _, err := c.w.Write(payload); err != nil {
		return err
	}
	// Out of the process's memory on every record: that is what makes
	// Ctrl-C free. fsync is on a timer instead, because a per-object fsync
	// would dominate a tree of small files.
	if err := c.w.Flush(); err != nil {
		return err
	}
	c.done[o.Key] = o
	if time.Since(c.lastSync) >= ckptSyncEvery {
		c.lastSync = time.Now()
		if err := c.f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes and syncs. The log is deliberately LEFT ON DISK: it is
// what makes the next run of the same graft cost only what changed.
func (c *Checkpoint) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if err := c.w.Flush(); err != nil {
		c.f.Close() //nolint:errcheck
		return err
	}
	if err := c.f.Sync(); err != nil {
		c.f.Close() //nolint:errcheck
		return err
	}
	return c.f.Close()
}

// Path is where the log lives, for a message that has to name it.
func (c *Checkpoint) Path() string { return c.path }

func encodeCheckObject(o *CheckObject) []byte {
	out := make([]byte, 0, 2+len(o.Key)+8*3+4+len(o.IDs)*keyLen+4+len(o.Body))
	var b [8]byte
	binary.LittleEndian.PutUint16(b[0:], uint16(len(o.Key)))
	out = append(out, b[0:2]...)
	out = append(out, o.Key...)
	binary.LittleEndian.PutUint64(b[:], uint64(o.Size))
	out = append(out, b[:]...)
	binary.LittleEndian.PutUint64(b[:], uint64(o.MtimeNS))
	out = append(out, b[:]...)
	binary.LittleEndian.PutUint64(b[:], uint64(o.Block))
	out = append(out, b[:]...)
	binary.LittleEndian.PutUint32(b[0:], uint32(len(o.IDs)))
	out = append(out, b[0:4]...)
	for _, id := range o.IDs {
		out = append(out, id[:]...)
	}
	binary.LittleEndian.PutUint32(b[0:], uint32(len(o.Body)))
	out = append(out, b[0:4]...)
	out = append(out, o.Body...)
	return out
}

func decodeCheckObject(p []byte) (*CheckObject, error) {
	need := func(n int) error {
		if len(p) < n {
			return errors.New("graft: short checkpoint record")
		}
		return nil
	}
	if err := need(2); err != nil {
		return nil, err
	}
	klen := int(binary.LittleEndian.Uint16(p[0:]))
	p = p[2:]
	if err := need(klen + 28); err != nil {
		return nil, err
	}
	o := &CheckObject{Key: string(p[:klen])}
	p = p[klen:]
	o.Size = int64(binary.LittleEndian.Uint64(p[0:]))
	o.MtimeNS = int64(binary.LittleEndian.Uint64(p[8:]))
	o.Block = int64(binary.LittleEndian.Uint64(p[16:]))
	n := int(binary.LittleEndian.Uint32(p[24:]))
	p = p[28:]
	if n < 0 || len(p) < n*keyLen+4 {
		return nil, errors.New("graft: short checkpoint record")
	}
	o.IDs = make([]chunkid.Identity, n)
	for i := 0; i < n; i++ {
		copy(o.IDs[i][:], p[i*keyLen:])
	}
	p = p[n*keyLen:]
	blen := int(binary.LittleEndian.Uint32(p[0:]))
	p = p[4:]
	if blen < 0 || len(p) < blen {
		return nil, errors.New("graft: short checkpoint record")
	}
	if blen > 0 {
		o.Body = append([]byte(nil), p[:blen]...)
	}
	return o, nil
}
