package superblock

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestAnImportEntryRoundTripsThroughTheSignature is the evolution rule
// applied to a new field: it must encode, decode and re-verify, because
// Verify re-encodes what it decoded.
func TestAnImportEntryRoundTripsThroughTheSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sb := &Superblock{
		FormatVersion: FormatV2, Generation: 3, NextInode: 99,
		Imports: []ImportEntry{{
			Path: "/theirs", Source: "pelican://fed/theirs", SourceBranch: "main",
			SourceGeneration: 7, ImportedUnixNano: 12345,
			Lineages: []LineagePair{{From: 0, To: 4242}, {From: 1234, To: 9999}},
			Files:    3, Inodes: 9, Bytes: 4096,
		}},
	}
	if err := sb.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(pub); err != nil {
		t.Fatalf("a superblock carrying an import entry does not verify: %v", err)
	}
	if len(got.Imports) != 1 || len(got.Imports[0].Lineages) != 2 {
		t.Fatalf("decoded %d imports with %d lineage rows", len(got.Imports), len(got.Imports[0].Lineages))
	}
	if got.Imports[0].Lineages[1].To != 9999 {
		t.Fatalf("lineage row round-tripped as %+v", got.Imports[0].Lineages[1])
	}
}

// TestAGenerationWithNoImportsEncodesNoImportKey is the other half of the
// evolution rule: an omitempty addition must leave every older document's
// encoding — and therefore its signature — exactly as it was.
func TestAGenerationWithNoImportsEncodesNoImportKey(t *testing.T) {
	sb := &Superblock{FormatVersion: FormatV2, Generation: 1}
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got := EncodedLen(sb.Imports); got != 1 {
		// A nil slice encodes as one byte (CBOR null) when encoded ALONE;
		// what matters is that the map key is absent from the document,
		// which is what the search below checks.
		t.Logf("EncodedLen(nil imports) = %d", got)
	}
	if idx := indexOf(raw, []byte("imports")); idx >= 0 {
		t.Fatalf("a superblock with no imports still carries the \"imports\" key at offset %d", idx)
	}
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestTakenLineagesUnionsEveryClaimAGenerationCarries is the invariant
// pickLineage rests on. Under-reporting here means a later `pelfs branch`
// draws a lineage an imported tree is already using, and the two hand out
// the same numbers for different files.
func TestTakenLineagesUnionsEveryClaimAGenerationCarries(t *testing.T) {
	sb := &Superblock{
		Fork:      &Fork{Lineage: 55},
		NextInode: FirstInode(55),
		Imports: []ImportEntry{
			{Lineages: []LineagePair{{From: 0, To: 100}, {From: 7, To: 200}}},
			{Lineages: []LineagePair{{From: 0, To: 300}}},
		},
	}
	taken := sb.TakenLineages()
	for _, want := range []uint32{0, 55, 100, 200, 300} {
		if !taken[want] {
			t.Errorf("lineage %d is claimed by this generation and TakenLineages omits it", want)
		}
	}
	if taken[999] {
		t.Error("TakenLineages claims a lineage nothing in the document names")
	}
	// A volume that has never been branched or imported still owns
	// lineage 0, because inode 1 is in it on every volume there has been.
	if !(&Superblock{}).TakenLineages()[0] {
		t.Error("a fresh volume does not claim lineage 0")
	}
	// And nil is answerable, because pickLineage may be handed a
	// generation it could not read.
	if !(*Superblock)(nil).TakenLineages()[0] {
		t.Error("a nil superblock does not claim lineage 0")
	}
}

// TestTheImportListIsInTheBudgetDiagnosis is the diagnosis half of the
// size guard: "the superblock is too big" is not actionable, and this is
// the field whose remedy is "stop importing" rather than "repack".
func TestTheImportListIsInTheBudgetDiagnosis(t *testing.T) {
	sb := &Superblock{}
	for i := range 200 {
		sb.Imports = append(sb.Imports, ImportEntry{
			Path:     "/some/reasonably/long/destination/path/number",
			Source:   "pelican://a-federation.example.org/a/long/prefix/name",
			Lineages: []LineagePair{{From: uint32(i), To: uint32(i + 1000)}},
		})
	}
	var found bool
	for _, c := range sb.Contributors() {
		if c.Field == "imports" {
			found = true
			if c.Entries != 200 {
				t.Errorf("the import contributor reports %d entries, want 200", c.Entries)
			}
			t.Logf("200 imports weigh %d bytes against a %d-byte budget", c.Bytes, ImportBudgetBytes)
		}
	}
	if !found {
		t.Fatal("Contributors does not report the import list, so a superblock full of them " +
			"would name the wrong field as the cause")
	}
}
