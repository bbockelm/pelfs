//go:build integration

// Package integration exercises pelfs's federation transport against a real
// Pelican federation (director + registry + origin, usually launched by
// scripts/integration-pelican.sh). It covers the object CRUD surface, the
// origin's ETag-on-overwrite behavior, and a full publish/resolve cycle
// against the live federation — everything except the FUSE mount itself.
//
// Required environment:
//
//	PELFS_TEST_PREFIX  e.g. pelican://localhost:8444/pelfs-test/it
//	PELFS_TEST_TOKEN   path to a bearer token with read+modify on the prefix
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/testvol"
)

func newStore(t *testing.T) pelicanobj.Store {
	t.Helper()
	prefix := os.Getenv("PELFS_TEST_PREFIX")
	if prefix == "" {
		t.Skip("PELFS_TEST_PREFIX not set; run via scripts/integration-pelican.sh")
	}
	s, err := pelicanobj.New(context.Background(), pelicanobj.Config{
		PrefixURL:    prefix,
		TokenPath:    os.Getenv("PELFS_TEST_TOKEN"),
		AcquireToken: false,
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("construct store for %s: %v", prefix, err)
	}
	return s
}

func TestFederationCRUD(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	payload := make([]byte, 3<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	key := "crud/blocks/0/1_0_3145728"
	if err := s.Put(ctx, key, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rc, err := s.Get(ctx, key, 0, -1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("Get read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("full read mismatch: %d vs %d bytes", len(got), len(payload))
	}

	rc, err = s.Get(ctx, key, 1<<20, 4096)
	if err != nil {
		t.Fatalf("ranged Get: %v", err)
	}
	got, _ = io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload[1<<20:(1<<20)+4096]) {
		t.Fatalf("ranged read mismatch (%d bytes)", len(got))
	}

	obj, err := s.Head(ctx, key)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if obj.Size != int64(len(payload)) {
		t.Fatalf("Head size = %d, want %d", obj.Size, len(payload))
	}

	entries, err := s.ListDir(ctx, "crud/blocks/0")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "1_0_3145728" {
		t.Fatalf("ListDir = %+v", entries)
	}

	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete (idempotent on missing): %v", err)
	}
	if _, err := s.Get(ctx, key, 0, -1); err == nil {
		t.Fatal("Get after Delete should fail")
	}
}

// TestOverwriteETag verifies the modern origin behavior pelfs's snapshot
// scheme depends on: overwriting an object in place succeeds, and the ETag
// changes with the content.
func TestOverwriteETag(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	key := "etag/current.db"

	if err := s.Put(ctx, key, strings.NewReader("generation one")); err != nil {
		t.Fatalf("initial Put: %v", err)
	}
	ki1, err := s.StatKey(ctx, key)
	if err != nil {
		t.Fatalf("StatKey: %v", err)
	}
	if ki1.ETag == "" {
		t.Fatal("origin returned no ETag; snapshot conflict detection would be inert")
	}

	time.Sleep(1100 * time.Millisecond) // outlast coarse mtime-based ETags
	if err := s.Put(ctx, key, strings.NewReader("generation two, longer")); err != nil {
		t.Fatalf("overwrite Put: %v", err)
	}
	ki2, err := s.StatKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if ki2.ETag == ki1.ETag {
		t.Fatalf("ETag unchanged across overwrite (%q)", ki1.ETag)
	}

	rc, err := s.Get(ctx, key, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "generation two, longer" {
		t.Fatalf("read after overwrite = %q", body)
	}
	_ = s.Delete(ctx, key)
}

// TestPackTailRangeRead exercises exactly the path behind the field-reported
// "bad pack magic" bootstrap failure: upload a pack-shaped object from a
// local FILE (the retry-safe DoPut path used by pack seals), then read back
// narrow ranges — including the trailing bytes, as the trailer probe does —
// and verify them byte-for-byte against the original.
func TestPackTailRangeRead(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	payload := make([]byte, 700_000) // spans multiple server read buffers
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	copy(payload[len(payload)-8:], []byte("PELFSPK1")) // trailer-like tail

	f, err := os.CreateTemp(t.TempDir(), "pack-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	const key = "packs/p-testtail-0001"
	if err := s.Put(ctx, key, f); err != nil {
		t.Fatalf("file-based Put: %v", err)
	}
	f.Close()

	// Full read-back sanity.
	rc, err := s.Get(ctx, key, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("full read mismatch: %d bytes vs %d", len(got), len(payload))
	}

	// Tail probe, exactly like packstore's trailer fetch.
	for _, probe := range []int64{16, 4096, 131072} {
		off := int64(len(payload)) - probe
		rc, err := s.Get(ctx, key, off, probe)
		if err != nil {
			t.Fatalf("tail range (off=%d len=%d): %v", off, probe, err)
		}
		got, err := io.ReadAll(io.LimitReader(rc, probe))
		rc.Close()
		if err != nil {
			t.Fatalf("tail range read (off=%d): %v", off, err)
		}
		if !bytes.Equal(got, payload[off:]) {
			t.Fatalf("tail range (off=%d len=%d) returned wrong bytes: got %d bytes, first mismatch hunting a range-request bug", off, probe, len(got))
		}
	}

	_ = s.Delete(ctx, key)
}

// TestPublishGenfsRoundTrip is the federation e2e: publish a generation
// into the REAL federation (packs, superblock backup, signed ref —
// exercising trailer range reads, ETag stat, and the pinning store over
// pelican-server), then resolve it back with genfs and verify every byte.
func TestPublishGenfsRoundTrip(t *testing.T) {
	ctx := context.Background()
	base := os.Getenv("PELFS_TEST_PREFIX")
	if base == "" {
		t.Skip("PELFS_TEST_PREFIX not set; run via scripts/integration-pelican.sh")
	}
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL:    fmt.Sprintf("%s/v2e2e-%d", base, time.Now().UnixNano()),
		TokenPath:    os.Getenv("PELFS_TEST_TOKEN"),
		AcquireToken: false,
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("construct store: %v", err)
	}

	// Source volume: a chunked multi-MiB file, an inline file, a symlink,
	// an xattr, and a hardlink pair, written through a write overlay.
	v := testvol.New(t, inner, testvol.Options{
		VolumeID: testvol.ParseUUID(t, "0f0e0d0c-0b0a-0908-0706-050403020100"),
	})
	bigContent := make([]byte, 3<<20)
	mrand.New(mrand.NewSource(42)).Read(bigContent)
	dirIno := v.Mkdir(testvol.RootInode, "d")
	bigIno := v.WriteFile(dirIno, "big.bin", bigContent)
	smallIno := v.WriteFile(dirIno, "small.txt", []byte("inline"))
	v.SetXattr(smallIno, "user.k", []byte("v"))
	v.Symlink(dirIno, "ln", "big.bin")
	v.Link(bigIno, dirIno, "big2")

	res := v.Publish(publish.Options{})
	t.Logf("published generation %d: %d chunks, %d catalogs, %d packs",
		res.Superblock.Generation, res.Stats.ChunksAdded, res.Stats.Catalogs, len(res.NewPacks))

	// TOFU-fetch the ref back and resolve the tree via genfs — every read
	// below is a real HTTP range request against pelican-server.
	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch ref: %v", err)
	}
	gfs, err := genfs.Open(ctx, genfs.Options{Inner: inner, SB: f.Superblock, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("genfs open: %v", err)
	}
	defer gfs.Close() //nolint:errcheck

	dn, err := gfs.Lookup(ctx, genfs.RootInode, "d")
	if err != nil {
		t.Fatalf("lookup d: %v", err)
	}
	bn, err := gfs.Lookup(ctx, dn.Inode, "big.bin")
	if err != nil {
		t.Fatalf("lookup big.bin: %v", err)
	}
	if bn.Nlink != 2 || bn.Length != int64(len(bigContent)) {
		t.Fatalf("big.bin node = %+v", bn)
	}
	got := make([]byte, len(bigContent))
	n, err := gfs.Read(ctx, bn.Inode, 0, got)
	if err != nil || n != len(bigContent) {
		t.Fatalf("read big.bin: n=%d err=%v", n, err)
	}
	if !bytes.Equal(got, bigContent) {
		t.Fatal("big.bin content mismatch through federation packs")
	}
	ln, err := gfs.Lookup(ctx, dn.Inode, "ln")
	if err != nil {
		t.Fatal(err)
	}
	if target, err := gfs.Readlink(ctx, ln.Inode); err != nil || target != "big.bin" {
		t.Fatalf("readlink = %q err=%v", target, err)
	}
	sn, err := gfs.Lookup(ctx, dn.Inode, "small.txt")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := gfs.GetXattr(ctx, sn.Inode, "user.k"); err != nil || string(v) != "v" {
		t.Fatalf("xattr = %q err=%v", v, err)
	}
}
