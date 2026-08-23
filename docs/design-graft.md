# Grafts: serving a foreign Pelican tree as part of a pelfs volume

Status: **spiked, and the spike reads.** A grafted tree is spidered,
block-digested, published into a signed generation, and read back
byte-for-byte through a real Linux kernel mount, with no copy of the data
under the volume's own prefix — and when the source changes underneath the
signed generation the read fails closed, naming the graft, the object and
the fix. Both runs are `scripts/graft-spike-docker.sh`, and the transcript
is in "The spike" below.

The design content is the six decisions, the interaction inventory, and the
ranked work. The prototype is deliberately small and is marked SPIKE in
every file it touches.

---

## The answer, in one paragraph

**Yes, and more cheaply than expected, because the format already had the
seam.** A graft is not a new content model — it is a second **location
layer**, and pelfs already separates the two: a `chunkref` stores
`{identity, llen, clen, alg, keyid}` and no pack name, because location
lives outside the catalog (`internal/genfs/genfs.go:155`). So a grafted
file's rows are ordinary chunkref rows, **no catalog format change at all**,
and the only additions are a signed `Grafts []GraftEntry` on the superblock
and a resolver consulted one branch earlier than the pack index. Identity
stays the same BLAKE3 function, which makes the two location layers
interchangeable and makes verification free of new mechanism. The two
places that fought back were both found by reading the code and both had
one-line answers already sitting in it: a write to a grafted file
un-grafts *that file* by taking the copy-up path the memtable already has
for holes (`internal/memtable/base.go`), and grafted identities must be
kept out of the dedup sidecar or a locally written file silently acquires a
dependency on a third party's URL. The two things that genuinely do not
work are that **encryption is a hard incompatibility** (an encrypted volume
literally cannot verify a grafted block — argued below, and it is a
mechanism problem, not a taste problem) and that **`--prefetch all` refuses
to mount a grafted volume today**, which is measured, not predicted. Both
are fixable; neither is a reason not to do this.

---

## What was built

| | |
|---|---|
| `internal/graft` | the index format (identity → object/offset/length, on `internal/packidx`), the spider, `Fetch`/`Put` |
| `internal/superblock` | `GraftEntry`, `Superblock.Grafts`, `GraftBudgetBytes` |
| `internal/genfs/graft.go` | the resolver, the reader-side veto, unconditional verification, `GraftStats` |
| `internal/publish/graftsource.go` | `GraftSource`: a `publish.Source` + `ContentProvider` over a spider result |
| `cmd/pelfs/graft.go` | `pelfs graft`, `pelfs graft --list`, the scheme allowlist, the mount's `GraftOpener` |
| `scripts/graft-spike-{test,docker}.sh` | the mount-backed spike |

`go build ./...`, `go vet ./...`, `go test ./...` are green (38 packages,
0 failures), and `scripts/mount-gate-docker.sh` still passes.

---

## Decision 1 — Expand at graft time. Confirmed, with a size limit

**Decision: spider now, emit an inode and chunkrefs per file into the
signed catalogs. A lazy subtree pointer is refused.**

The reason is the one you gave and the code agrees with it: a lazy pointer
lets the tree change without a new generation, and "a generation is an
immutable signed statement of a namespace" is the property everything else
rests on — `refs.Fetch` refuses a generation older than one it has
accepted, `VerifyChain` hashes wire bytes, retention reasons about
generations as fixed sets. A pointer would make the namespace a function of
when you looked.

But expansion has a price and it should be stated in numbers rather than
waved at.

**Catalog rows.** A grafted file costs exactly what a packed file costs:
one `node` row, one `edge` row, and `ceil(size / block)` `chunkref` rows.
At the 1 MiB default block a 1 TB graft is ~1M chunkref rows, which is the
same order as a 1 TB packed tree at the 4 MiB average CDC chunk (~256k
rows) — within 4x, not a different regime. `SMax` splitting therefore
behaves exactly as it does for packed content and needs no graft-specific
handling: a grafted directory that grows past the threshold gets a nested
catalog like any other.

**The graft index.** Measured, not estimated:
`TestIndexSizePerBlock` builds 20,000 blocks and gets **48.2 bytes per
block** (32-byte identity + 16-byte record, plus the sampled index and the
object-key string table). So:

| graft size | blocks at 1 MiB | index |
|---|---|---|
| 1 GB | 1,024 | 49 KB |
| 1 TB | 1.05M | 50 MB |
| 100 TB | 105M | 5.0 GB |

**When is a graft too big to expand?** Two different limits bind, and they
bind at very different sizes.

- The **superblock** does not bind at all, and that is by construction: only
  the graft *roots* live there, one entry per graft. A realistic entry
  (long CVMFS-shaped paths) encodes to **215 bytes**, so
  `GraftBudgetBytes = 16 KiB` carries **~76 roots**. The superblock never
  grows with the number of grafted files, which is the same discipline
  `Manifests` imposed on the pack list.
- The **index fetch** binds first, and today it binds hard, because the
  spike fetches each index **whole** at mount. At 50 MB (1 TB) that is a
  slow but survivable mount; at 5 GB (100 TB) it is not a mount at all.
  This is a spike limitation and not a design one: `packidx` already
  supports exactly the fix — `Header.Window(key)` plus a sampled prefix, the
  ranged-window lookup `internal/mpi/remote.go` uses for the multi-pack
  index at the same 100M-object target. The graft index was deliberately
  built on `packidx` so that this is a change of caller, not of format.

So the honest answer: **with the ranged-window fetch implemented, a graft
scales to the same 100M objects the rest of the format targets.** Without
it — i.e. today — keep grafts under about 10 GB of source data.

The other cost is time, and it is unavoidable: the spider **streams every
byte of the source once**. That is O(source) bandwidth at graft time and
O(0) storage forever, against a copy's O(source) in both, forever. It is
also the moment at which the source is known to be self-consistent, and
nothing detects a source mutated mid-walk except the per-object
length check the spider already does.

---

## Decision 2 — Fixed blocks with per-block digests. `--verify=digest` is refused

**Decision: fixed-size blocks with a per-block digest, and that is the only
mode. The whole-object-digest alternative is not offered, not even as a
flag.**

I came in expecting to agree with you about `--verify=blocks|digest` and
the code talked me out of it. The argument is already written down in this
repo, from the other direction, in `internal/pelicanobj/fedstore.go:240`:

> GetUnverified reads an object through a RANGED transfer, which the
> Pelican client deliberately does not checksum: **a server-advertised
> digest covers a whole object and cannot be applied to a range**, so
> verification is skipped.

A `--verify=digest` graft would therefore be a mode in which **no read is
ever verified**, because every read of a grafted file is a range. Not
"partial reads are unverified" — *all* of them, since a 4 KiB `read()` of a
2 GB file cannot be checked against that file's digest without downloading
the 2 GB. The only way to make it mean anything is to fetch whole objects
always, which is the copy you are trying to avoid.

And the offer is worth less than it looks even at graft time. The saving a
service digest buys is "don't stream the source once". But you must stream
it once anyway to know the object *lengths* the catalog records agree with
the bytes — and the spike's own failure case is a **one-byte change with
the length unchanged**, which no amount of `HEAD` would catch.

So: blocks, always. Three consequences, stated rather than buried.

**The block digest IS the chunk identity.** BLAKE3-256 of the plaintext
block, `chunkid.Hasher`, the same function as everywhere else. This is the
single best thing about the design and it was free: the two location layers
become interchangeable. If a graft block happens to equal a pack chunk,
either location serves the same bytes and reading from the pack is simply
cheaper. No new verification mechanism exists; `entrycodec.AlgNone` with
`clen == llen` and `keyid == 0` passes through `decodeChunk` untouched.

**A graft never dedups against packed content.** Correct, as you said, and
the reason is boundaries: FastCDC cuts where the content says, a graft cuts
every 1 MiB. Two grafts of the same tree dedup perfectly with each other;
a graft and a pack of the same file share nothing. Accepted.

**Block size is a different trade from chunk size.** A CDC chunk is sized
to maximize dedup across edits. A graft block is sized to trade index size
against read amplification, and nothing about it dedups. 1 MiB is the
default; the knob is `pelfs graft --block`.

### Verification is unconditional, unlike for packed chunks

`genfs` verifies packed chunks only when `fs.verify` is set (unencrypted
volumes, checked once at cache fill). Grafted blocks are verified **always,
with no configuration that disables it**, and the asymmetry is deliberate:

> A packed chunk came from an object this volume wrote, under a prefix its
> own keys authorize, and the Merkle path to the superblock signature
> already covers it. A grafted block came from a party with no obligation
> to this volume and no signature over its content — the identity check is
> the ONLY thing standing between a changed source and a wrong read.

### Small files are inlined, and stop being grafted

This fell out of the spike rather than being designed, and it is right.
Publish stores a file at or under `InlineMax` (2048 bytes) in the catalog
by rule, and `ContentProvider` has no shape for "inline this but here are
chunk records". So the spider keeps the bytes of files under
`graft.InlineKeep` (64 KiB) and publish inlines them.

Those files are **copied into the volume and are not grafted at all**. That
is a feature: they are then covered by the catalog's identity and the
superblock signature, they no longer depend on the source, and serving a
200-byte file from a catalog that was fetched anyway costs nothing where
serving it from a foreign origin costs a request. `pelfs graft` reports the
count and bytes out loud, because a user counting "grafted files" would
otherwise be counting the wrong thing. In the spike, 1 of 4 files
(21 bytes) was inlined.

---

## Decision 3 — Ungraft at FILE granularity. Your framing is stricter than necessary, and here is the proof

**Decision: a write un-grafts the file it touches, and nothing else. A new
file inside a grafted directory is an ordinary local file and its grafted
siblings are untouched. Whole-tree ungrafting is refused.**

You asked for a concrete argument either way. Here it is, and then here is
the test that runs it.

**The mechanism already exists and needed no invention.** `memtable.Adopt`
(`internal/memtable/base.go:67`) gives an inode a writable body starting
from the base generation's version, and it already has two shapes it
declines to adopt *by reference* and falls back to reading for: inline
bodies, and holes. A graft is a third such shape, and the change is
literally the same three lines:

```go
if c.External {
    return s.adoptByReading(ctx, ino, length)
}
```

The bytes come through the base read path — **so they are verified against
the graft's identities on the way**, which means a copy-up cannot launder
changed source bytes into a pack — and are re-chunked and packed like any
other write. Cost: one file download, once.

**Why not adopt by reference (which would be cheaper)?** Because that is
where your instinct is right. Adoption by reference would leave the file
half its own and half somebody else's: the written span in a pack, the
untouched spans still pointing at a URL that may change under it, and an
mtime that no longer matches the graft a freshness check would compare
against. That file is not a graft any more and should not pretend to be
one. So *at file granularity* your invariant holds exactly: the moment you
write to it, the file leaves the graft entirely.

**Why not the whole tree?** Because nothing forces it, and the cost is
enormous. The overlay records a per-inode change; the seal reuses every
inode it did not touch; the graft list carries forward in the superblock.
A `touch` in a grafted tree is one file's work.

**The spike tests exactly this**, and it tests it the only way that can't
be faked — by **deleting the source object** for the file that was written:

```
wrote 5 bytes into a grafted file, and created a new file beside it
packs grew from 2682 to 2102431 bytes
PASS: the written file was materialized into packs (2099749 bytes) -- it is ungrafted
-- now DELETE the source object for the file that was written --
PASS: the written file reads with its source object DELETED -- fully local
PASS: its grafted siblings are untouched and still served from the source
PASS: a file created inside a grafted directory is an ordinary local file
```

### The cases that genuinely force wider materialization — I could not find one

You asked me to name a case that forces it. I went looking at rename,
chmod, and directory ops, and the honest answer is **there isn't one**,
for a structural reason: the graft index is keyed by **identity**, and the
superblock's `GraftEntry.Path` is used for reporting, not for resolution.
Nothing about where a grafted file *sits* in the namespace affects whether
its bytes resolve.

- **Rename a grafted directory.** The overlay writes edges; the chunkrefs
  underneath are untouched and still resolve by identity. The graft's
  recorded `Path` becomes a lie for reporting purposes — `pelfs graft
  --list` would name a path that no longer exists — which is a **cosmetic**
  defect with a real fix (record the graft's root inode alongside its path,
  or re-derive the path at report time). It is not a correctness defect,
  and it must not be allowed to become one by making resolution
  path-dependent.
- **`chmod` one grafted file.** An attribute override in the overlay. The
  seal reuses the content records via `ContentReuser` and the file stays
  grafted with a new mode. Nothing materializes.
- **`chmod -R` a grafted tree.** N attribute overrides, no content
  materialization, one seal. Cheap.
- **Delete a grafted file.** A whiteout edge. The blocks stay in the graft
  index, unreferenced, which is harmless — the index is an immutable
  hash-named object, and an entry nothing references costs bytes in the
  index and nothing else.

The one thing I could not test and would want to before shipping is a
**rename of a grafted directory across a nested-catalog boundary**, because
that is where the overlay's rebase machinery is most intricate. Stated as
unverified rather than claimed.

---

## Decision 4 — Fail closed, and fsck needs a severity axis it does not have

**Decision: never serve an unverified byte; error naming the graft, the
source object, the byte range, and the command that fixes it.**

Implemented, and this is the spike's second half. One byte changed at
offset 1,500,000 of a 2.5 MB source file, length unchanged:

```
dd: error reading '.../mnt/ext/data/multiblock.bin': Input/output error

genfs: graft /ext: http://127.0.0.1:18997/ext/data/multiblock.bin [1048576,+1048576)
hashes to 8a7b79e1…, the generation says 5dfc7171… — the graft source has changed
since it was spidered, so these bytes are NOT what this volume published; run
`pelfs graft --refresh /ext` to republish it
```

Four things a person needs, in one sentence: which graft, which object and
range, that the **source** is what changed rather than the volume, and what
to run. And the failure is **per block**: the same file's unchanged blocks
still read, and the other grafted files are unaffected. Both are asserted
in the spike.

The mount also fails closed at `Open` if a **graft index** cannot be
fetched or does not hash to what the superblock says. That is a deliberate
asymmetry with `PackIndexes`, which are hints with a fallback: a graft is
the *only* record of where its bytes live, so a mount that shrugged would
look healthy and answer an error for every file under it. Same class as
`Manifests`, same treatment.

`--refresh` is named in the error and is **not implemented**. It is
mechanically a re-spider that publishes a new generation with a new index —
the same code path `pelfs graft` already runs — plus a diff report so a
user learns what moved.

### What `fsck` should do — and the blocker in front of it

Two modes, matching the existing `--deep` precedent:

- **Cheap (default with `--check-grafts`): one `HEAD` per source object.**
  `Index.Objects()` already returns exactly that list. Compare size and
  ETag against what the graft recorded. This is `checkPacks`'s existing
  shape (`internal/fsck/fsck.go:399` stats each pack and compares size), so
  it is a new call site rather than new machinery.
- **Deep (`--deep --check-grafts`): re-read and re-hash every block.** The
  bounded verifier pool at `internal/fsck/walk.go:314` already does this
  for pack chunks.

**Does a stale graft fail `fsck` or warn?** It must **warn**, and that is
the blocker: `fsck` has no warning tier. Every `Kind` is damage,
`Report.OK()` is `len(Problems) == 0`, and any problem exits 1
(`cmd/pelfs/fsck.go:77`). Adding `KindGraftStale` under that model would
make `pelfs fsck` exit 1 on a perfectly healthy volume every time an
upstream file is republished — which is what a graft is *for*. So a
`Severity` field on `Problem`, with `OK()` counting only errors, has to
land **before** graft checking does. That is a change to `fsck`'s contract
and should be its own commit.

Note also that `checkChunkRef` (`internal/fsck/walk.go:263`) will report
**every grafted file as damaged** today — `chunk %s resolves in no listed
pack`. Making fsck graft-aware is not optional polish; without it `fsck` is
unusable on a grafted volume.

---

## Decision 5 — The interaction inventory

This is where a design like this dies, so it is a table with a verdict per
row. **Severity** is: 🔴 breaks today, 🟠 wrong-but-quiet, 🟡 works, needs a
decision, 🟢 fine as is.

| Subsystem | What it assumes | What a graft does to it | Verdict |
|---|---|---|---|
| `genfs.ContentOf` (`read.go:152`) | every non-hole identity is in a listed pack, else abort | **would abort every seal over a grafted subtree.** Fixed in the spike: the graft table is consulted first, and `Content.External` is set. | 🔴 → fixed |
| `--prefetch all` (`genfs/prefetch.go`) | everything referenced is in a pack; failures are fatal | **refuses to mount.** Measured: `prefetch: 4 pack(s) could not be made local ([chunk 68c99c16…: present in no listed pack …]); refusing to mount`. Must skip grafts and count them separately; prefetching foreign bytes should be **opt-in** (`--prefetch grafts`), never the default. | 🔴 |
| `fsck` (`walk.go:263`) | ditto | **reports every grafted file as `missing-chunk`, exit 1.** Needs graft-awareness *and* a severity axis (Decision 4). | 🔴 |
| Dedup sidecar (`publish/dedup.go`, `rememberReusedChunks`) | an identity in the set means "a listed pack holds these bytes" | **silent data loss** if graft identities enter it: a locally written file's chunk is elided from upload because a third party holds the same block, and no graft record names it. **Not a coincidence** — a graft block is a whole file whenever the file is under the block size, and CDC cuts such a file into one chunk of the same bytes. Fixed in the spike via `Content.External` → `rememberExcept`. | 🟠 → fixed |
| `memtable.Adopt` (`base.go:67`) | base records can be carried by reference | would leave a written file half-grafted. Fixed: `External` → `adoptByReading` (Decision 3). | 🟠 → fixed |
| `reach` / `gc` | `Report.Unresolved` counts identities in no pack; it is "damage, fsck's business" | grafted identities inflate `Unresolved` silently, destroying it as a damage signal. **GC itself is safe** — it only deletes under `packs/`, `mpi/`, `manifest/` in this volume's prefix, so it can neither collect a foreign object nor a graft index it doesn't know about. That last part is the actual bug: `grafts/` has **no live-set key space**, so index objects leak forever. Needs a `scanHashNamed` arm. | 🟠 |
| `repack` | drives from the pack side | **never touches external content**, correctly. But `repackedSuperblock` copies field-by-field (`execute.go:800`) — `Grafts` survives by value-copy today, which is luck rather than intent and should be explicit. `Worthwhile` judges from pack count alone, so a 95%-graft volume is judged by its 5%. | 🟡 |
| Decoded-chunk arena | it amortizes **decode**; keyed by identity hex | a graft block has no decode to amortize — it amortizes a **round trip**, worth strictly more. Sharing it is right, and sharing it **by identity** is what makes it safe: the arena's shard function reads chars 0–1 of the key and its ghost filter chars 0–16, so a synthetic key like `graft:<url>:<off>` would collapse every graft block into one of 64 shards. Open question: the arena is a fixed reservation *tuned against decode cost*, and a graft-heavy mount competes for it in a different currency. | 🟡 |
| `merge` (`sameRef`, `apply.go:400`) | location is deliberately ignored when comparing refs; `ProvidedPacks` is the only location statement | `sameRef` would call a packed ref and an external ref with the same identity "equal", and the merged generation could inherit a foreign dependency the other branch never named. There is **no `ProvidedGrafts`**, so a merge that takes a grafted file publishes chunkrefs with no location. Today `merge` passes no `GraftOpener`, so it **fails loudly** rather than silently — the safe direction, and not a solution. | 🔴 |
| `rescue` | reconstructs from **packs alone** | a graft cannot be rescued from packs — by construction, since the bytes were never in one. Worse, a graft-only generation writes no pack, so there is **no carrier for the superblock backup** and it is unrescuable at all. Mitigated in practice by catalogs always being packed; should be stated in `RootStatus` ("and these grafts were not verified"). | 🟠 |
| Encryption | the federation-visible surface carries nothing content- or name-derived | **hard incompatibility.** Decision 6. | 🔴 refuse |
| `stats` | one `WrapStorage` site (`mountgen.go:561`) counts transport ops | a graft's store is a **different store instance** and is silently uncounted. `GraftStats` exists in the spike (resolved/fetches/bytes/failures/mismatch, deliberately separate from chunk counters — "how much of this mount's traffic went to a third party" is a question an aggregate cannot answer) but is not yet published into the JSON summary. | 🟡 |
| `--prefetch` budget | sizes from the signed pack list | a graft has no pack sizes; a budget would need `GraftEntry.Bytes` (which is recorded). | 🟡 |
| `branch` / `fast-forward` | copies the head's bytes | carries `Grafts` correctly, but a fast-forward can import a foreign dependency onto `main` with no reachability check. | 🟡 |
| Catalog format | `chunkref` is fully packed; `node.Flags` is unused | **no change needed.** This is the headline: grafts touch the catalog format not at all. `node.Flags` remains available if a "this inode is grafted" marker is ever wanted for reporting. | 🟢 |
| `retention` / grace window | ages hash-named objects | graft indexes are immutable and hash-named, so they fit the existing model exactly — once `grafts/` is added to the swept key spaces. | 🟢 |

---

## Decision 6 — Encryption is refused, and the reason is mechanism, not taste

**Decision: a graft on an encrypted volume is refused at the writer AND at
the reader. There is no flag.**

I expected to argue this on confidentiality grounds and found a harder
reason first, in `internal/genfs`'s own package comment:

> On encrypted volumes identity is keyed BLAKE3 under the volume identity
> key, **which genfs does NOT hold** (only the unwrapped DEK arrives in
> Options) — there the AES-GCM tag, opened under the DEK, already
> authenticates every entry, so identity recomputation is skipped.

Now put a grafted block into that. It is `AlgNone`, `keyid 0`, so it has
**no GCM tag**. And identity recomputation is skipped because the reader
holds no identity key. The result is that a grafted block on an encrypted
volume would be **the only unauthenticated byte in the system, on the
volume that asked hardest for authentication.** That is not a policy
preference; it is an absence of any available mechanism.

The confidentiality argument is the same shape and worth stating anyway,
because it is sharper than "plaintext at a third party is bad".
`docs/design-packfs.md` promises that catalogs and shards are encrypted
*specifically because filenames leak otherwise*, and that
"federation-visible object names are never content-derived". A graft
publishes, in the clear inside the signed superblock, **a foreign URL
naming exactly what is inside the volume** — plus the byte-range access
pattern of everyone who reads it. Keyed identity exists to make
content-confirmation attacks impossible without the key; a graft hands the
answer over in the superblock. The feature and the promise contradict each
other internally.

There is a third, quieter one. `docs/design-packfs.md` claims "honest
declassify semantics — an encrypted base can NOT be forked into a public
branch by pointer games, because the shared objects stay ciphertext." A
graft **is** the pointer game that property was written to rule out,
arriving from the other direction.

So: refused. The reader-side refusal is the load-bearing one, because it
holds whatever wrote the generation:

```
genfs: this generation names 1 graft(s) and the volume is encrypted; grafted
blocks carry no AEAD tag and their identity is keyed, so nothing here can
verify them
```

I note that this repo's usual pattern for encrypted volumes is
**degrade-and-document** (identity verification silently off, GCM standing
in) rather than refusal. That pattern does not extend here because there is
nothing left to degrade *to* — there is no second check for the graft case
the way the GCM tag is a second check for the packed case.

---

## Decision 7 — Synthesized metadata: 0444/0555, owned by the grafting user

**Decision: grafted files are `0444`, grafted directories `0555`, and both
are owned by the uid/gid of whoever ran `pelfs graft`.**

A spider learns size and mtime. There is no uid, gid or mode at the other
end of a Pelican `GET`. Three sub-decisions:

**Mode is read-only, and that is a statement rather than a default.** A
grafted file cannot be written in place — the first byte written un-grafts
it — so a writable mode would advertise something the tree does not do. It
also sidesteps `fsperm`'s first-match-wins rule, under which a mode like
`0044` denies its own owner (`internal/fsperm/perm.go:244`, and the v0.2.0
permission change in the CHANGELOG). `0555` for directories matches
`initvolume.go`'s `0755` in spirit minus write.

**Ownership is the grafting user's, not the source's and not root's.** This
is the one that would have bitten. `internal/idmap` translates **exactly
one** identity — the volume root's — to the mounting process; every other
uid passes through untouched into the other-class arm of the permission
check. So reporting a plausible upstream `uid 4242, mode 0640` would make
the tree unreadable on every machine whose uid differs, with no mechanism
to rescue it.

**And squashing is defensible here specifically**, which is worth saying
because this codebase argues *against* squashing at length.
`internal/idmap`'s package comment refuses a general squash because it
makes `chown` invisible, so `tar -p`, `cp -a` and installers appear to
succeed having done nothing — "worse than failing". **That objection does
not reach a graft**, because a read-only tree has no `chown` to make
invisible. It is the one place the standing argument does not apply, and
the design leans on that rather than ignoring it.

Verified in the spike: `mode=444 uid=0 gid=0` for files, `mode=555` for
directories (uid 0 because the container runs as root).

One fidelity loss, stated plainly: **a grafted tree has no symlinks.** A
spider sees objects, not links. Where the source was made by publishing a
POSIX tree, its symlinks are gone. `GraftSource.Readlink` says so rather
than inventing something.

---

## Decision 8 — Security: two vetoes, and only one of them protects a reader

**Decision: a writer-side scheme allowlist (`pelican://`, `osdf://`;
`http(s)://` with a warning; `file://` refused absolutely), and — the one
that matters — a reader-side veto at mount, `genfs.Options.GraftOpener`.**

You identified the non-obvious risk exactly: a grafted volume shared with
other people makes **their** clients fetch URLs **you** chose, from their
network position, with their credentials. Packs do not have this property
because a pack lives under the volume's own prefix, and a reader who trusts
the volume already trusts that prefix.

And you are right that the signature does not help: **the URL being inside
a signed catalog makes it tamper-evident, not safe.** The signature says
"the volume's author chose this", which is the whole of what it says. The
author may be careless, or may be someone who obtained the signing key, and
either way the fetch happens from the reader's side.

So the enforcement point has to be the **reader**, and in the spike it is a
function the mount supplies:

```go
// GraftOpener builds a transport for one graft SOURCE prefix. […]
// It is also THE READER'S VETO. […] Returning an error here refuses the
// source and fails the mount, which is the only place that decision can
// be enforced. Nil refuses every graft.
GraftOpener func(ctx context.Context, source string) (pelicanobj.Store, error)
```

`nil` refuses every graft, which is the correct default for a caller that
has not thought about it — and it is why `merge` and `testvol`, which pass
no opener, fail loudly on a grafted volume rather than quietly fetching.

**`file://` is refused absolutely**, and not as a policy preference: a
graft is part of a shared, signed generation, and a local path resolves to
a *different tree on every machine that mounts it*. A volume carrying one
is not a filesystem — it is a filesystem whose contents depend on who is
looking.

**Should a reader be able to see grafts?** Yes, and cheaply — the answer
comes out of the superblock with no index fetch. `pelfs graft --list` is
implemented:

```
/ext <- http://127.0.0.1:18997/ext (6 blocks of 1048576, 3970037 bytes)
```

and every mount of a grafted volume logs one line per source before it
serves a byte:

```
graft source: reads under a grafted path will fetch http://127.0.0.1:18997/ext
```

**What is not implemented** and should be, in order of how much it matters:

1. **A `--no-graft` mount flag**, which mounts the volume with grafted
   paths returning `EACCES` rather than refusing the whole mount. Today the
   only choices are "open every source" and "fail to mount".
2. **A federation allowlist** — `--graft-allow pelican://osg-htc.org/…` —
   so a site can say which third parties its users' clients may be pointed
   at, as configuration rather than per-mount vigilance.
3. **Same-federation-only as a policy option.** I considered making this
   the *default* and decided against it: the CVMFS-shaped use case this
   feature exists for is precisely cross-federation, so a same-federation
   default would refuse the motivating case. It belongs as a site policy
   knob, off by default, rather than as a format rule.
4. **A first-use prompt or pin**, analogous to the volume-key
   trust-on-first-use warning that already exists. A graft source silently
   changing between mounts of the same branch is a real event, and the
   machinery for pinning-and-warning is already in `refs`.

---

## The spike

`scripts/graft-spike-docker.sh` → `scripts/graft-spike-test.sh`. Docker,
because macOS denies the shell access to its own FUSE mounts; a real Linux
kernel, real FUSE, `--network none`, a `fakeorigin` serving **two prefixes**
— `/vol` is the pelfs volume, `/ext` is the foreign tree. Exit 0.

### The tree, and the claim that nothing was copied

```
source tree: 4 files, 3970037 bytes
grafted 3 files (3970016 bytes) at /ext from http://127.0.0.1:18997/ext
1 files under 65536 bytes were stored inline in the catalog (21 bytes) and are not grafted
6 blocks of 1048576 bytes digested in 5ms; index is 459 bytes

grafted tree:      3970037 bytes at http://127.0.0.1:18997/ext
volume pack bytes: 2689 bytes under http://127.0.0.1:18997/vol/packs
the data was NOT repacked locally: packs are 0% of the tree
```

**2,689 bytes of volume storage for a 3,970,037-byte tree** — 0.07%, and
those bytes are the catalogs, not the data. This is checked, not printed:
the script fails if the packs are as large as the source.

### The good read

```
-r--r--r-- 1 root root 1048576 Aug 23 19:53 exactblock.bin
-r--r--r-- 1 root root 2621440 Aug 23 19:53 multiblock.bin
-r--r--r-- 1 root root      21 Aug 23 19:53 small.txt

diff -r --no-dereference $WORK/ref $WORK/mnt/ext
PASS: every grafted byte read back correctly through the mount
PASS: a 2000-byte read across the 1 MiB block boundary is correct
PASS: grafted files are read-only (0444), directories 0555
```

The tree is diffed against a **reference copy**, not against the origin
directory, so the test that mutates the origin next cannot also mutate what
it compares to. The ranged read straddling a block boundary is the property
a whole-object digest could not have verified (Decision 2).

### The failure

One byte at offset 1,500,000; the file's **length unchanged**, so nothing
about the namespace looks wrong.

```
-- the UNTOUCHED files must still read fine --
PASS: the other grafted files are unaffected

-- the mutated block must FAIL, not return wrong bytes --
dd: error reading '…/mnt/ext/data/multiblock.bin': Input/output error
0 bytes copied

ERROR pelfs: Read: returning EIO for an unrecognized error: genfs: graft /ext:
http://127.0.0.1:18997/ext/data/multiblock.bin [1048576,+1048576) hashes to
8a7b79e18a96b98ac30a6287c32eb8ec9405514f03e11b3f82d4c76d20a52a78, the generation
says 5dfc71717d9f562de745c6870a9af3ce870a2614ca366c0814f3591939f7ed63 — the graft
source has changed since it was spidered, so these bytes are NOT what this volume
published; run `pelfs graft --refresh /ext` to republish it

PASS: failed closed, naming the graft, the source, the object and the fix
PASS: the unchanged blocks of the SAME file still read (per-block granularity)
```

Note `Read: returning EIO for an unrecognized error`. That is the raw-FUSE
binding saying it has no errno for this, and it is **a finding, not
noise**: a graft-integrity failure deserves its own error class rather than
falling through the catch-all. The user-visible `EIO` is right; the log line
admitting it is unrecognized is not.

### Ungraft on write

Section 5, quoted in full under Decision 3. The load-bearing move is
deleting the source object for the written file: it reads anyway.

### And the one that fails today

```
6. EVIDENCE, not a pass/fail: what --prefetch all does today
mount came up: no
ERROR pelfs: prefetch: 4 pack(s) could not be made local ([chunk 68c99c16…:
present in no listed pack chunk 5b1a264d…: present in no listed pack …]);
refusing to mount
```

Recorded as evidence rather than asserted as pass or fail, because it is
a measurement of the gap rather than a test of the fix.

### What the spike does NOT prove

Said plainly, because it is a spike:

- **It grafts over an empty root.** `pelfs init` then `pelfs graft`. Grafting
  into a volume that already has content needs the source to merge the
  previous generation's tree with the spidered one — the job `mergeSource`
  already does over two generations. **Nothing in the read path or the
  format changes**; the writer is what is unfinished. This is ranked work
  item 1.
- **The index is fetched whole at mount.** Fine at 459 bytes, not fine at
  50 MB. Ranked item 3.
- **The spider is single-threaded** and holds a `map[Identity]struct{}` of
  every block (~5 GB at the 100M-block target). Ranked item 4.
- **Grafted reads are not coalesced.** `fillChunks` skips them, so a
  multi-block read is one request per block. Adjacent graft blocks are
  *more* reliably contiguous in their source object than pack entries are
  in a pack, so this should be easy and is ranked item 5.
- **No `--refresh`, no `--remove`, no fsck integration, no stats
  publication.**
- **No test of concurrent readers of one graft block**, of a source that
  fails mid-read, or of a graft across a nested-catalog boundary.

---

## Ranked implementation work

Effort is calendar-days for someone who knows this codebase.

| # | Work | Why it is here | Effort |
|---|---|---|---|
| 1 | **Graft into a populated volume** — a `Source` that splices a spidered tree over the previous generation, on `mergeSource`'s pattern | without it the feature is `init`-then-`graft` only, which is not the use case | 3–4 d |
| 2 | **`fsck`: a `Severity` axis, then graft awareness** | `fsck` reports every grafted file as damaged and exits 1 today. The severity change must land first and is a contract change | 2 d + 2 d |
| 3 | **`--prefetch`: skip grafts, count them, add opt-in `--prefetch grafts`** | `--prefetch all` refuses to mount a grafted volume (measured) | 1–2 d |
| 4 | **Ranged-window index lookup** (`packidx.Header.Window`, as `mpi/remote.go` does) | the only thing between the current design and the 100M-object target | 2–3 d |
| 5 | **`pelfs graft --refresh` and `--remove`** | named in a user-facing error message that currently cannot be followed | 2 d |
| 6 | **`grafts/` in the retention key space** | index objects leak forever today | 0.5 d |
| 7 | **Coalesce adjacent graft blocks in `fillChunks`** | one request per 1 MiB block on every sequential read | 1 d |
| 8 | **`merge`: `ProvidedGrafts`, and make `sameRef` location-aware** | merge on a grafted volume fails loudly now; making it work needs both | 2–3 d |
| 9 | **Publish `GraftStats` into the stats JSON; wrap the graft store in `stats.WrapStorage`** | third-party traffic is invisible in the summary | 1 d |
| 10 | **Spider: parallelism, and `extsort` instead of an in-memory identity set** | ~5 GB of RSS at the target scale, and O(source) time single-streamed | 2 d |
| 11 | **`--no-graft` and `--graft-allow` mount flags** | the reader's veto is all-or-nothing today | 1 d |
| 12 | **A distinct errno/error class for graft-integrity failure** | `returning EIO for an unrecognized error` in the log | 0.5 d |
| 13 | **Re-derive `GraftEntry.Path` at report time, or record the root inode** | renaming a grafted directory makes `--list` lie | 0.5 d |
| 14 | **Arena sizing for graft-heavy mounts** | the arena is tuned against decode cost, and a graft trades in round trips | investigation |

Items 1–3 are the difference between a spike and a feature. 4 is the
difference between a feature and one that scales.

---

## Why this might be a bad idea

Five reasons, in descending order of how much they worry me.

**1. It makes a pelfs volume's availability the intersection of two
storage systems.** Today, a volume is readable if its own prefix is
readable. A grafted volume is readable if its prefix **and** every graft
source are readable, by every reader, from wherever they are. The
availability of the whole is the product of the parts, and one of the parts
belongs to someone with no obligation to you. Everything else here is
engineering; this one is arithmetic.

**2. "Fail closed" is correct and will still feel like a bug.** The
spike's error message is as good as I know how to make one — it names the
graft, the object, the range, both hashes, what changed, and the fix. It
will still arrive as `Input/output error` in the middle of somebody's job,
hours after an upstream maintainer republished a file for a perfectly good
reason. A graft turns an ordinary upstream event into a read failure in a
filesystem, and no amount of error-message quality changes that. It is
worth asking whether the real use case wants a graft or wants
`pelfs` to *ingest* the tree once and be done.

**3. The security property is genuinely new and users will not model
it.** Every other object a pelfs mount fetches lives under a prefix the
reader already decided to trust. A graft is the first time reading a file
sends your client somewhere the volume's author picked. The mitigations
here are real but they are all *opt-in vigilance* — a log line, a
`--list`, a veto function nobody will supply a policy for. The safe
default would be to refuse grafts unless the mount explicitly allows them,
and I did not choose that default because it would make the feature
unusable out of the box. That is a trade I would want you to make
deliberately rather than inherit from this spike.

**4. The interaction surface is large and mostly not done.** Look at the
inventory table: four 🔴 rows and five 🟠. The spike closed the two that
would have caused silent wrongness, and the rest are loud failures — which
is the right order — but a feature that requires touching `fsck`,
`prefetch`, `merge`, `retention`, `stats` and `rescue` before it is
coherent is a feature with a long tail. The estimate above sums to roughly
four to five weeks, and I would not trust it to better than 50%.

**5. It is a second way to do something pelfs already does well.** The
chunker plus cross-generation dedup means ingesting a tree you don't own is
not that expensive, and the result has none of the properties above: it is
self-contained, verifiable from packs alone, rescuable, mergeable,
prefetchable, and encryptable. A graft buys you "don't store the bytes" and
pays for it with every one of those. The case where that trade is clearly
right is a *large* tree you would never store and *mostly do not read* — a
CVMFS software area, which is presumably why CVMFS has the feature. The
case where it is clearly wrong is a tree small enough to ingest. I would
want a size threshold in the documentation, and I would want `pelfs graft`
to say something when you graft a tree that is under it.

None of these is a reason to stop. The first three are reasons to be
careful about defaults, and the last two are reasons to be honest in the
documentation about when *not* to use it.
