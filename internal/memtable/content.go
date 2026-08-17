package memtable

import "sort"

// ref is one contiguous run of one extent's bytes placed at a file
// offset. It is the stand-in for what an ocontent row holds: a handle,
// never a place. Skip exists because a later write can bite a piece out
// of the middle of an earlier extent — the extent's bytes are still
// wanted, just not all of them, and the extent is append-only so they
// cannot be rewritten in place.
type ref struct {
	FileOff int64
	Skip    int
	Length  int
	Handle  Handle
}

func (r ref) end() int64 { return r.FileOff + int64(r.Length) }

// content is one inode's byte map: refs sorted by file offset, never
// overlapping. Gaps are holes and read as zeros.
type content struct {
	refs []ref
	size int64
}

// punch removes [off, off+n) from the map and reports, for each handle,
// the net change in reference count. Callers turn that into live-set
// updates on the owning tables: a handle that loses its last reference is
// an extent that died in memory.
func (c *content) punch(off int64, n int64, dropped map[Handle]int) {
	if n <= 0 {
		return
	}
	end := off + n
	out := c.refs[:0]
	for _, r := range c.refs {
		if r.end() <= off || r.FileOff >= end {
			out = append(out, r)
			continue
		}
		// Head survives: the part before the new write.
		if r.FileOff < off {
			head := r
			head.Length = int(off - r.FileOff)
			out = append(out, head)
		}
		// Tail survives: the part after. Both surviving means the write
		// landed inside the extent and split it, so the handle now has one
		// more reference than it did, not one fewer.
		if r.end() > end {
			tail := r
			tail.Skip += int(end - r.FileOff)
			tail.Length = int(r.end() - end)
			tail.FileOff = end
			out = append(out, tail)
		}
		survivors := 0
		if r.FileOff < off {
			survivors++
		}
		if r.end() > end {
			survivors++
		}
		dropped[r.Handle] += survivors - 1
	}
	c.refs = out
	sort.Slice(c.refs, func(i, j int) bool { return c.refs[i].FileOff < c.refs[j].FileOff })
}

// insert places a whole extent at off, displacing whatever was there.
func (c *content) insert(off int64, length int, h Handle, dropped map[Handle]int) {
	c.punch(off, int64(length), dropped)
	c.refs = append(c.refs, ref{FileOff: off, Length: length, Handle: h})
	sort.Slice(c.refs, func(i, j int) bool { return c.refs[i].FileOff < c.refs[j].FileOff })
	if end := off + int64(length); end > c.size {
		c.size = end
	}
}

// truncate resizes the file, dropping or trimming refs past the new size.
// Growing only moves the size: the new region is a hole.
func (c *content) truncate(size int64, dropped map[Handle]int) {
	if size < c.size {
		c.punch(size, c.size-size, dropped)
	}
	c.size = size
}

// overlapping returns the refs intersecting [off, off+n), in order.
func (c *content) overlapping(off int64, n int64) []ref {
	end := off + n
	i := sort.Search(len(c.refs), func(i int) bool { return c.refs[i].end() > off })
	var out []ref
	for ; i < len(c.refs) && c.refs[i].FileOff < end; i++ {
		out = append(out, c.refs[i])
	}
	return out
}

// handlesInOrder returns the distinct handles this content still names,
// in order of first appearance, restricted to those want accepts. That
// order is the stream CDC runs over: chunk boundaries should follow the
// file's byte order, not the order writes happened to arrive.
//
// Liveness needs no separate consultation here — a handle reachable from
// a content ref is live by definition, and one that is not simply does
// not appear.
func (c *content) handlesInOrder(want func(Handle) bool) []Handle {
	var seen map[Handle]struct{}
	var out []Handle
	for _, r := range c.refs {
		if !want(r.Handle) {
			continue
		}
		if seen == nil {
			seen = make(map[Handle]struct{})
		}
		if _, dup := seen[r.Handle]; dup {
			continue
		}
		seen[r.Handle] = struct{}{}
		out = append(out, r.Handle)
	}
	return out
}
