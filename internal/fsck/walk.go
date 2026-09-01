package fsck

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// catJob is one catalog to descend into: its identity, the inode of the
// directory it covers, and that directory's namespace path.
type catJob struct {
	idHex string
	ino   uint64
	path  string
}

// walk descends the whole namespace, catalog by catalog. Nested catalogs
// are queued rather than recursed into, so exactly one path catalog is
// open at a time however deep the tree nests (shards are the exception —
// see openShard).
func (c *checker) walk(ctx context.Context, root catalog.Reader, rootHex string) {
	seenInode := make(map[uint64]bool)
	visited := map[string]bool{rootHex: true}
	queue := []catJob{{idHex: rootHex, ino: rootInode, path: "/"}}

	// The root directory itself: its node row must exist, and it counts.
	if _, err := root.Stat(int64(rootInode)); err != nil {
		c.problem(KindDanglingDirent, "/", "the root inode has no node row: %v", err)
	}
	seenInode[rootInode] = true
	c.rep.Dirs++
	c.checkCatalogOrder(root, "/")

	cat := root
	for i := 0; i < len(queue); i++ {
		if err := ctx.Err(); err != nil {
			return
		}
		j := queue[i]
		if i > 0 {
			cat = c.openCatalogObject(ctx, j.idHex, j.path, KindMissingCatalog, KindBadCatalog)
			if cat == nil {
				continue
			}
			c.rep.Catalogs++
			c.checkCatalogOrder(cat, j.path)
		}
		c.walkDir(ctx, cat, j, j.ino, j.path, seenInode, make(map[uint64]bool), visited, &queue)
		if i > 0 {
			c.releaseCatalog(cat, j.idHex)
		}
	}
}

// checkCatalogOrder runs the O(n) sortedness pass an encoding may leave
// to fsck. A reader that binary-searches an unsorted array returns wrong
// answers rather than unsafe ones, so nothing else would ever notice.
func (c *checker) checkCatalogOrder(cat catalog.Reader, path string) {
	oc, ok := cat.(catalog.OrderChecker)
	if !ok {
		return
	}
	if err := oc.CheckOrder(); err != nil {
		c.problem(KindBadCatalog, path, "%v", err)
	}
}

// walkDir checks one directory and recurses into the subdirectories that
// live in the SAME catalog; transition points are appended to the queue.
// walked guards against an edge cycling back to an ancestor within one
// catalog — a corrupt catalog must not hang fsck.
func (c *checker) walkDir(ctx context.Context, cat catalog.Reader, j catJob, ino uint64, dirPath string,
	seenInode, walked map[uint64]bool, visited map[string]bool, queue *[]catJob) {
	if walked[ino] {
		c.problem(KindCycle, dirPath, "directory inode %d is reachable more than once within catalog %s", ino, j.idHex)
		return
	}
	walked[ino] = true

	dirents, nesteds, err := cat.Readdir(int64(ino))
	if err != nil {
		c.problem(KindBadCatalog, dirPath, "readdir inode %d in catalog %s: %v", ino, j.idHex, err)
		return
	}
	byName := make(map[string]catalog.Dirent, len(dirents))
	for _, d := range dirents {
		byName[string(d.Name)] = d
	}
	// A transition point carries BOTH halves in the parent catalog: the
	// dirent (so lookup and stat never fetch the child) and the nested
	// locator (so descent can). One without the other is corruption.
	nestedByName := make(map[string][]byte, len(nesteds))
	for _, n := range nesteds {
		name := string(n.Name)
		nestedByName[name] = n.CatalogIdentity
		if _, ok := byName[name]; !ok {
			c.problem(KindTransition, path.Join(dirPath, name),
				"nested locator %x has no dirent half in catalog %s", n.CatalogIdentity, j.idHex)
		}
	}

	for _, d := range dirents {
		name := string(d.Name)
		childPath := path.Join(dirPath, name)
		n, err := cat.Stat(d.Inode)
		if err != nil {
			if errors.Is(err, catalog.ErrNotExist) {
				c.problem(KindDanglingDirent, childPath, "dirent names inode %d, which has no node row in catalog %s", d.Inode, j.idHex)
			} else {
				c.problem(KindBadCatalog, childPath, "stat inode %d in catalog %s: %v", d.Inode, j.idHex, err)
			}
			continue
		}
		if n.Type != d.Type {
			c.problem(KindTypeMismatch, childPath, "dirent type %d, node row type %d", d.Type, n.Type)
		}
		cino := uint64(d.Inode)
		switch n.Type {
		case catalog.TypeDir:
			if !seenInode[cino] {
				seenInode[cino] = true
				c.rep.Dirs++
			}
			if id, ok := nestedByName[name]; ok {
				idHex := hex.EncodeToString(id)
				if len(id) != 32 {
					c.problem(KindTransition, childPath, "nested locator is %d bytes, want 32", len(id))
					continue
				}
				// Content addressing permits two transition points to name
				// the same catalog; descending twice would only repeat
				// byte-identical work.
				if visited[idHex] {
					continue
				}
				visited[idHex] = true
				*queue = append(*queue, catJob{idHex: idHex, ino: cino, path: childPath})
				continue
			}
			c.walkDir(ctx, cat, j, cino, childPath, seenInode, walked, visited, queue)
		case catalog.TypeSymlink:
			if !seenInode[cino] {
				seenInode[cino] = true
				c.rep.Symlinks++
			}
			if _, err := cat.Symlink(d.Inode); err != nil {
				c.problem(KindContent, childPath, "symlink inode %d has no target row: %v", d.Inode, err)
			}
		case catalog.TypeFile:
			if seenInode[cino] {
				continue // another link to a file already checked
			}
			seenInode[cino] = true
			c.rep.Files++
			c.rep.Bytes += n.Length
			c.checkFile(ctx, cat, j, n, childPath)
		default:
			// Special files (fifo/dev/socket) have no content records.
			seenInode[cino] = true
		}
	}
}

// checkFile verifies one regular file's content records. Promoted
// (nlink > 1) files keep their content in an inode shard; their node row
// stays in the path catalog, which is the routing genfs performs at read
// time and the invariant checked here.
func (c *checker) checkFile(ctx context.Context, cat catalog.Reader, j catJob, n catalog.Node, filePath string) {
	content := cat
	ino := uint64(n.Inode)
	if n.Nlink > 1 {
		sh := c.shardFor(ino)
		if sh == nil {
			c.problem(KindShardRouting, filePath, "promoted inode %d (nlink %d) is covered by no shard", ino, n.Nlink)
			return
		}
		scat := c.openShard(ctx, hex.EncodeToString(sh.Identity[:]), shardPath(sh))
		if scat == nil {
			return // the shard's own failure is already reported
		}
		sn, err := scat.Stat(n.Inode)
		if err != nil {
			c.problem(KindShardRouting, filePath, "promoted inode %d has no record in shard %d-%d: %v",
				ino, sh.FirstInode, sh.LastInode, err)
			return
		}
		if sn.Length != n.Length {
			c.problem(KindShardRouting, filePath, "shard record says %d bytes, the path catalog's node row says %d",
				sn.Length, n.Length)
		}
		content = scat
	}

	inline, err := content.Inline(n.Inode)
	if err != nil {
		c.problem(KindContent, filePath, "read inline row of inode %d: %v", ino, err)
		return
	}
	if inline != nil {
		c.rep.InlineFiles++
		if int64(len(inline)) != n.Length {
			c.problem(KindContent, filePath, "inline data is %d bytes, node length is %d", len(inline), n.Length)
		}
		return
	}

	// catalog.Chunks already refuses a chunk list whose logical lengths do
	// not sum to the node length; that is the structural check, so its
	// error is a problem rather than a fatality.
	refs, err := content.Chunks(n.Inode)
	if err != nil {
		c.problem(KindChunkRefs, filePath, "%v", err)
		return
	}
	if refs == nil {
		if n.Length > 0 {
			c.problem(KindContent, filePath, "node length is %d but the file has neither inline data nor chunkrefs", n.Length)
		}
		return
	}
	for i := range refs {
		r := &refs[i]
		if r.LLen < 0 || r.CLen < 0 {
			c.problem(KindChunkRefs, filePath, "extent %d has negative lengths (llen %d, clen %d)", i, r.LLen, r.CLen)
			continue
		}
		if r.LogicalOffset < 0 || r.LogicalOffset > math.MaxInt64-r.LLen {
			c.problem(KindChunkRefs, filePath, "extent %d overflows the logical offset space (offset %d, llen %d)", i, r.LogicalOffset, r.LLen)
			continue
		}
		if r.Identity == nil {
			continue // hole: llen zeros, no object
		}
		if len(r.Identity) != 32 {
			c.problem(KindChunkRefs, filePath, "extent %d identity is %d bytes, want 32", i, len(r.Identity))
			continue
		}
		c.checkChunkRef(ctx, r, filePath)
	}
}

// checkChunkRef resolves one chunkref against the identity index. This is
// the DEFAULT-mode check and it is presence-only: it proves the location
// layers still contain an entry with that identity and the recorded
// stored length, not that the bytes are the right bytes. Only Deep reads
// them.
//
// THE INDEX HOLDS BOTH LAYERS, so a grafted chunkref resolves here like
// any other. It used to fall through to missing-chunk — "resolves in no
// listed pack" — for EVERY file under a graft, which is true and
// misleading in the same sentence: a grafted chunk is in no pack BY
// DESIGN, because its location is a foreign object rather than a hole.
// genfs.ContentOf and genfs.Prefetch had the same absence check and were
// taught the same thing; this was the third and last one.
//
// An identity in neither layer is still missing-chunk and still damage.
func (c *checker) checkChunkRef(ctx context.Context, r *catalog.ChunkRef, filePath string) {
	idHex := hex.EncodeToString(r.Identity)
	var id [32]byte
	copy(id[:], r.Identity)
	// The chunkref's own clen picks between duplicate placements, so a
	// chunk stored in two packs at two compressed lengths is checked
	// against the one it claims to be rather than an arbitrary one.
	loc, at, ok := c.locate(id, r.CLen)
	if !ok {
		// Report per file: the same lost chunk in ten files is ten damaged
		// files, which is what a human needs to see.
		c.problem(KindMissingChunk, filePath,
			"chunk %s resolves in no listed pack%s", idHex, c.orInAnyGraft())
		return
	}
	if loc.graft >= 0 {
		c.noteGraftRef(loc, filePath)
		c.checkGraftChunkRef(r, loc, idHex, filePath)
	} else if loc.length != r.CLen {
		c.problem(KindChunkRefs, filePath, "chunk %s is %d stored bytes in pack %s, the chunkref says clen %d",
			idHex, loc.length, loc.pack, r.CLen)
	}
	if c.seenChunk(at) {
		return
	}
	c.rep.Chunks++
	if loc.graft >= 0 {
		c.rep.GraftChunks++
	}
	// Deep mode is per LAYER: --deep reads packed chunks, --grafts=deep
	// reads external ones, and a caller may ask for either without the
	// other — re-reading a 10 TB graft is a different decision from
	// re-reading the packs this volume wrote.
	if (loc.graft < 0 && c.o.Deep) || (loc.graft >= 0 && c.graftDepth() == GraftDeep) {
		select {
		case c.verify <- chunkJob{
			id: id, idHex: idHex, alg: r.Alg, keyID: r.KeyID, llen: r.LLen, clen: r.CLen, path: filePath,
		}:
		case <-ctx.Done():
		}
	}
}

// orInAnyGraft is the half-sentence that keeps missing-chunk honest on a
// grafted volume: on one, "in no listed pack" is not the whole claim.
func (c *checker) orInAnyGraft() string {
	if len(c.grafts) == 0 {
		return ""
	}
	return fmt.Sprintf(" and in none of the %d graft(s) this generation names", len(c.grafts))
}

// seenChunk reports (and records) whether a chunk identity has already
// been counted. Content addressing means one identity backs many files;
// fetching or counting it twice would misreport the generation.
//
// The mark is a BIT PER INDEX POSITION rather than a set of identities.
// Every chunk that gets this far resolved in the index, so the index
// already holds each identity exactly where a lookup found it, and a
// second copy of a hundred million 32-byte keys buys nothing over a
// hundred million bits. At that scale it is the difference between 12 MB
// and several gigabytes.
func (c *checker) seenChunk(at int) bool {
	word, bit := at/64, uint(at%64)
	if c.seen == nil {
		c.seen = make([]uint64, (c.index.Len()+63)/64)
	}
	if c.seen[word]&(1<<bit) != 0 {
		return true
	}
	c.seen[word] |= 1 << bit
	return false
}

// shardFor finds the shard whose inclusive inode range covers ino.
func (c *checker) shardFor(ino uint64) *superblock.ShardEntry {
	for i := range c.o.SB.Shards {
		sh := &c.o.SB.Shards[i]
		if sh.FirstInode <= ino && ino <= sh.LastInode {
			return sh
		}
	}
	return nil
}

// startVerifiers opens deep mode's worker pool. Chunks are verified AS
// THE WALK FINDS THEM rather than collected into a work list and run
// afterwards.
//
// One pool serves both location layers. A grafted block's verification is
// the same shape as a packed chunk's — fetch a range, hash it, compare
// against the identity a signed catalog names — and it wants the same
// bounded concurrency for the same reason, so it would take an argument
// to give it a second pool rather than to share this one.
//
// The work list was the last structure here that grew with object count:
// one entry per distinct chunk, each carrying a path, which at a hundred
// million chunks is gigabytes held for the length of the walk. Streaming
// it costs nothing — the pool is bounded, the walk blocks when every
// worker is busy, which is exactly the backpressure a work list was
// hiding — and it starts fetching during the walk instead of after it.
func (c *checker) startVerifiers(ctx context.Context) {
	if !c.o.Deep && !(c.graftDepth() == GraftDeep && len(c.grafts) > 0) {
		return
	}
	workers := c.o.Workers
	if workers <= 0 {
		workers = 8
	}
	// The workers range over a LOCAL copy of the channel: stopVerifiers
	// clears the field, and a worker that had not yet evaluated the range
	// would otherwise be reading it as that write lands.
	ch := make(chan chunkJob)
	c.verify = ch
	for range workers {
		c.verifiers.Go(func() {
			for j := range ch {
				if ctx.Err() != nil {
					// Drain rather than return: the walk is still sending, and
					// a worker that stops reading would block it forever.
					continue
				}
				c.verifyChunk(ctx, j)
			}
		})
	}
}

// stopVerifiers closes the pool and waits for it. Safe to call when deep
// mode is off, and safe to call twice.
func (c *checker) stopVerifiers() {
	if c.verify == nil {
		return
	}
	ch := c.verify
	c.verify = nil
	close(ch)
	c.verifiers.Wait()
}

func (c *checker) verifyChunk(ctx context.Context, j chunkJob) {
	// Present: checkChunkRef only queues chunks that resolved.
	loc, _, _ := c.locate(j.id, j.clen)
	if loc.graft >= 0 {
		c.verifyGraftChunk(ctx, j, loc)
		return
	}
	stored, err := c.readPackRange(ctx, loc)
	if err != nil {
		c.problem(KindChunk, j.path, "chunk %s: %v", j.idHex, err)
		return
	}
	var key []byte
	if j.keyID != 0 {
		if len(c.o.DEK) == 0 {
			c.problem(KindChunk, j.path, "chunk %s is encrypted (keyid %d) but no DEK was provided", j.idHex, j.keyID)
			return
		}
		key = c.o.DEK
	}
	// On encrypted volumes this decode IS the integrity check: the GCM tag
	// fails closed on any tampering (see the package comment).
	plain, err := entrycodec.Decode(stored, uint8(j.alg), key)
	if err != nil {
		c.problem(KindChunk, j.path, "chunk %s: %v", j.idHex, err)
		return
	}
	if int64(len(plain)) != j.llen {
		c.problem(KindChunk, j.path, "chunk %s decodes to %d bytes, the chunkref says llen %d", j.idHex, len(plain), j.llen)
		return
	}
	if c.verifyIdentity {
		if id := c.hasher.Sum(plain); id.Hex() != j.idHex {
			c.problem(KindChunk, j.path, "chunk %s hashes to %s", j.idHex, id.Hex())
			return
		}
	}
	c.mu.Lock()
	c.rep.ChunksVerified++
	c.mu.Unlock()
}
