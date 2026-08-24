package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
	"github.com/bbockelm/pelfs/internal/ui"
)

// A volume with no signing key: created on purpose, read only with consent,
// and refused the moment its identity changes shape.

// unsignedVol is a prefix, a state directory and the transport, without a
// key anywhere — the throwaway setup the feature exists for.
type unsignedVol struct {
	prefix   string
	stateDir string
	inner    pelicanobj.Store
}

func newUnsignedVol(t *testing.T) *unsignedVol {
	t.Helper()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	prefix := srv.URL + "/vol"
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: prefix})
	if err != nil {
		t.Fatal(err)
	}
	return &unsignedVol{prefix: prefix, stateDir: t.TempDir(), inner: inner}
}

func (v *unsignedVol) args(rest ...string) []string {
	return append([]string{"--state-dir", v.stateDir, "--no-lease"}, append(rest, v.prefix)...)
}

// captureUI runs f with the UI redirected, so a test can assert on the
// words a user actually sees rather than on an internal predicate.
func captureUI(t *testing.T, f func()) string {
	t.Helper()
	var buf bytes.Buffer
	restore := ui.SetOutput(&buf, ui.Plain)
	defer restore()
	f()
	return buf.String()
}

// TestInitUnsignedCreatesNoKeyAndSaysSo. Three things at once, because
// they are one promise: no key file is left anywhere, the head really
// carries no signature, and the command says what was given up.
func TestInitUnsignedCreatesNoKeyAndSaysSo(t *testing.T) {
	v := newUnsignedVol(t)
	out := captureUI(t, func() {
		if code := cmdInit(v.args("--unsigned")); code != 0 {
			t.Fatalf("pelfs init --unsigned = %d", code)
		}
	})
	if !strings.Contains(out, "UNSIGNED") {
		t.Fatalf("init said nothing about the volume being unsigned: %q", out)
	}
	if _, err := os.Stat(filepath.Join(v.stateDir, "v2-signing.key")); !os.IsNotExist(err) {
		t.Fatal("`init --unsigned` minted a signing key; the whole point is that there is none to carry")
	}
	s, err := refs.New(v.inner, v.stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The machine that created it consented by typing the flag, so it needs
	// no flag afterwards.
	f, err := s.Fetch(context.Background(), "main")
	if err != nil {
		t.Fatalf("the creating machine cannot read its own volume: %v", err)
	}
	if !f.Superblock.IsUnsigned() {
		t.Fatal("`init --unsigned` published a signed generation")
	}
}

// TestInitUnsignedRefusesASigningKey: the two flags are contradictory
// requests and must not be silently reconciled in either direction.
func TestInitUnsignedRefusesASigningKey(t *testing.T) {
	v := newUnsignedVol(t)
	if code := cmdInit(v.args("--unsigned", "--signing-key", "/nonexistent")); code == 0 {
		t.Fatal("--unsigned with --signing-key was accepted")
	}
}

// TestAnotherMachineNeedsTheOptIn. The pin is local, so a second state
// directory is a second reader — which is exactly the case the refusal is
// for, and the one that cannot be reproduced by re-running a command in the
// same directory.
func TestAnotherMachineNeedsTheOptIn(t *testing.T) {
	v := newUnsignedVol(t)
	if code := cmdInit(v.args("--unsigned")); code != 0 {
		t.Fatalf("init: %d", code)
	}
	other := t.TempDir()
	s, err := refs.New(v.inner, other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(context.Background(), "main"); err == nil {
		t.Fatal("a second reader mounted an unsigned volume with no opt-in")
	}
	lax, err := refs.NewWithPolicy(v.inner, other, refs.Policy{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lax.Fetch(context.Background(), "main"); err != nil {
		t.Fatalf("--allow-unsigned did not let the second reader in: %v", err)
	}
}

// TestFsckReportsUnsignedAsAWarningNotDamage: an unsigned volume is not a
// broken one, so `pelfs fsck` must still exit 0 and still say the word.
// --strict is where a user asks for the opposite.
func TestFsckReportsUnsignedAsAWarningNotDamage(t *testing.T) {
	v := newUnsignedVol(t)
	if code := cmdInit(v.args("--unsigned")); code != 0 {
		t.Fatalf("init: %d", code)
	}
	out := captureStdout(t, func() {
		if code := cmdFsck(v.args()); code != 0 {
			t.Fatalf("pelfs fsck on an unsigned volume = %d, want 0 (it is not damaged)", code)
		}
	})
	if !strings.Contains(out, "warning: unsigned") {
		t.Fatalf("fsck did not report the volume as unsigned: %q", out)
	}
	if !strings.Contains(out, "generation is consistent") {
		t.Fatalf("fsck must still call an undamaged generation consistent: %q", out)
	}
	if code := cmdFsck(v.args("--strict")); code != 1 {
		t.Fatalf("pelfs fsck --strict on an unsigned volume = %d, want 1", code)
	}
}

// TestRotateToUnsignedAndBack walks the whole mode-change story on a real
// volume: signed, downgraded, refused by an outside reader, then signed
// again.
func TestRotateToUnsignedAndBack(t *testing.T) {
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	prefix := srv.URL + "/vol"
	ctx := context.Background()
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: prefix})
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	keyPath := filepath.Join(stateDir, "v2-signing.key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tv := testvol.New(t, inner, testvol.Options{SigningKey: key})
	tv.WriteFile(testvol.RootInode, "keep.txt", []byte("still here"))
	tv.Publish(publish.Options{})

	mine, err := refs.New(inner, stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mine.Fetch(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	// A SECOND reader, pinned to the key before the downgrade. It is the
	// one whose refusal is the point.
	otherDir := t.TempDir()
	other, err := refs.New(inner, otherDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Fetch(ctx, "main"); err != nil {
		t.Fatal(err)
	}

	args := []string{"--state-dir", stateDir, "--no-lease"}
	if code := cmdRotate(append(append([]string{}, args...), "--to-unsigned", "--apply", prefix)); code != 0 {
		t.Fatalf("pelfs rotate --to-unsigned --apply = %d", code)
	}

	// The machine that ran it carries on.
	f, err := mine.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("the downgrading machine cannot read its own volume: %v", err)
	}
	if !f.Superblock.IsUnsigned() {
		t.Fatal("the head is still signed after --to-unsigned")
	}
	// The key is archived, not live and not gone.
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("the live signing key survived a downgrade; the next seal would try to use it")
	}
	if !hasRetiredKey(t, stateDir) {
		t.Fatal("the retired key was deleted rather than archived; every pre-downgrade tag is now unreadable forever")
	}
	// Everybody else stops, and no flag on their side changes that.
	if _, err := other.Fetch(ctx, "main"); err == nil {
		t.Fatal("a reader pinned to the key accepted the downgrade")
	}
	lax, err := refs.NewWithPolicy(inner, otherDir, refs.Policy{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lax.Fetch(ctx, "main"); err == nil {
		t.Fatal("--allow-unsigned lifted a downgrade refusal")
	}

	// And back. A NEW identity: the old key is retired, so this is not a
	// restoration and the readers stay broken either way.
	if code := cmdRotate(append(append([]string{}, args...), "--to-signed", "--apply", prefix)); code != 0 {
		t.Fatalf("pelfs rotate --to-signed --apply = %d", code)
	}
	f, err = mine.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("after --to-signed: %v", err)
	}
	if f.Superblock.IsUnsigned() {
		t.Fatal("the head is still unsigned after --to-signed")
	}
	if f.Superblock.SigningPub == toArray32(key.Public().(ed25519.PublicKey)) {
		t.Fatal("--to-signed reused the retired key; it must mint a new identity, or a downgrade would be a " +
			"reversible way to launder a key back into service")
	}
}

// TestRotateToUnsignedIsReportOnlyByDefault. The destructive form has to be
// typed, and the report has to be the same report either way.
func TestRotateToUnsignedIsReportOnlyByDefault(t *testing.T) {
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	prefix := srv.URL + "/vol"
	ctx := context.Background()
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: prefix})
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "v2-signing.key"),
		[]byte(hex.EncodeToString(key)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	testvol.New(t, inner, testvol.Options{SigningKey: key})
	s, err := refs.New(inner, stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	out := captureUI(t, func() {
		if code := cmdRotate([]string{"--state-dir", stateDir, "--no-lease", "--to-unsigned", prefix}); code != 0 {
			t.Fatalf("dry run = %d", code)
		}
	})
	if !strings.Contains(out, "EVERY OTHER CLIENT") {
		t.Fatalf("the dry run did not say who it breaks: %q", out)
	}
	after, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if after.Superblock.Generation != before.Superblock.Generation {
		t.Fatal("a report-only run published a generation")
	}
	if !hasLiveKey(t, stateDir) {
		t.Fatal("a report-only run retired the signing key")
	}
}

// TestUnsignedRoundTrip is the whole feature in one pass, at the layer a
// mount uses: create unsigned, write, seal, reopen COLD (a fresh cache, a
// fresh reader) and read the bytes back exactly.
//
// Cold matters. A warm genfs would answer out of a cache the writer filled,
// which proves nothing about whether an unsigned generation can be
// published, fetched through the trust boundary, and resolved from the
// federation the way any other one is.
func TestUnsignedRoundTrip(t *testing.T) {
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatal(err)
	}
	tv := testvol.New(t, inner, testvol.Options{Unsigned: true})
	if tv.SigningKey() != nil {
		t.Fatal("an unsigned volume minted a key")
	}
	// Content that spans more than one chunk, so the read path resolves
	// real chunkrefs out of a pack rather than inline bytes.
	body := bytes.Repeat([]byte("unsigned round trip \x00\x01\x02"), 40000)
	tv.WriteFile(testvol.RootInode, "big.bin", body)
	tv.WriteFile(testvol.RootInode, "small.txt", []byte("hello"))
	tv.Publish(publish.Options{})
	// A second seal, because a CHECKPOINT of an unsigned volume is the step
	// that would silently mint a key if any writer decided for itself how
	// to sign (superblock.SignAs).
	tv.WriteFile(testvol.RootInode, "second.txt", []byte("and again"))
	res := tv.Publish(publish.Options{})
	if !res.Superblock.IsUnsigned() {
		t.Fatal("a seal onto an unsigned volume produced a signed generation")
	}

	// COLD: a reader that has never seen this volume, with consent.
	readerDir := t.TempDir()
	rs, err := refs.NewWithPolicy(inner, readerDir, refs.Policy{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	f, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("cold fetch of an unsigned volume: %v", err)
	}
	gfs, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: f.Superblock, CacheDir: filepath.Join(readerDir, "gencache"),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	defer gfs.Close() //nolint:errcheck
	for _, want := range []struct {
		name string
		body []byte
	}{
		{"big.bin", body},
		{"small.txt", []byte("hello")},
		{"second.txt", []byte("and again")},
	} {
		node, err := gfs.LookupPath(ctx, want.name)
		if err != nil {
			t.Fatalf("lookup %s: %v", want.name, err)
		}
		got := make([]byte, len(want.body))
		n, err := gfs.Read(ctx, node.Inode, 0, got)
		if err != nil || n != len(want.body) {
			t.Fatalf("read %s: n=%d err=%v", want.name, n, err)
		}
		if !bytes.Equal(got, want.body) {
			t.Fatalf("%s came back different", want.name)
		}
	}
}

// TestASealOnAnUnsignedVolumeMintsNoKey pins the failure that would be
// silent: the key resolver every writer shares must return "no key" rather
// than generating one, or the first checkpoint of a throwaway volume would
// sign it and every reader's unsigned pin would start refusing.
func TestASealOnAnUnsignedVolumeMintsNoKey(t *testing.T) {
	sb := &superblock.Superblock{FormatVersion: superblock.FormatV2, Generation: 4}
	sb.Unsign()
	dir := t.TempDir()
	path := filepath.Join(dir, "v2-signing.key")
	key, err := loadOrCreateSigningKey(path, sb)
	if err != nil {
		t.Fatalf("loadOrCreateSigningKey on an unsigned head: %v", err)
	}
	if key != nil {
		t.Fatal("a key was returned for an unsigned volume")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a key file was created for an unsigned volume")
	}
}

// TestUnsignedMountSealsWithoutAKey drives the SEAL path a writable mount
// runs — the checkpoint and the seal at unmount — on a volume with no key.
//
// It is the failure that would otherwise be silent and permanent: the key
// resolver every writer shares used to mint a key when it found none, so a
// throwaway volume's first checkpoint would have signed it, and every
// reader's unsigned pin would have started refusing a volume that was
// working a minute earlier.
func TestUnsignedMountSealsWithoutAKey(t *testing.T) {
	g := newGenSessionMode(t, true, true)
	ctx := context.Background()
	if !g.sb.IsUnsigned() {
		t.Fatal("the fixture volume is signed")
	}
	writeFile(t, g.ov, "work.txt", "in progress")
	res, err := g.sealLocked(ctx, false)
	if err != nil {
		t.Fatalf("seal on an unsigned volume: %v", err)
	}
	if res == nil {
		t.Fatal("the seal published nothing")
	}
	if !res.Superblock.IsUnsigned() {
		t.Fatal("a seal signed an unsigned volume; every reader's pin now refuses it")
	}
	if _, err := os.Stat(filepath.Join(g.stateDir, "v2-signing.key")); !os.IsNotExist(err) {
		t.Fatal("the seal minted a signing key for a volume that deliberately has none")
	}
	// And the reader path agrees: the published head still reads under the
	// unsigned pin, with no flag.
	s, err := refs.New(g.inner, g.stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("re-reading what the seal published: %v", err)
	}
	if f.Superblock.Generation != res.Superblock.Generation {
		t.Fatalf("head is generation %d, the seal published %d",
			f.Superblock.Generation, res.Superblock.Generation)
	}
}

// TestStatusMarksAnUnsignedMount: someone scanning `pelfs status` must see
// it on the line they already read.
func TestStatusMarksAnUnsignedMount(t *testing.T) {
	root := t.TempDir()
	dir := volDirIn(root, "pelican://fed/pfx")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	rec := mountInfo{
		PID: os.Getpid(), Prefix: "pelican://fed/pfx", MountPoint: "/mnt/x",
		Branch: "main", Unsigned: true, Started: time.Now(),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mount.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if code := cmdStatus([]string{"--state-dir", root}); code != 0 {
			t.Fatalf("pelfs status = %d", code)
		}
	})
	if !strings.Contains(out, "unsigned") {
		t.Fatalf("`pelfs status` did not mark the unsigned mount: %q", out)
	}
}

func toArray32(k ed25519.PublicKey) [32]byte {
	var a [32]byte
	copy(a[:], k)
	return a
}

func hasLiveKey(t *testing.T, stateDir string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(stateDir, "v2-signing.key"))
	return err == nil
}

func hasRetiredKey(t *testing.T, stateDir string) bool {
	t.Helper()
	ents, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), "v2-signing.key.retired-") {
			return true
		}
	}
	return false
}
