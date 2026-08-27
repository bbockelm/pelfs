package genfs

import (
	"errors"
	"fmt"
)

// The graft-integrity error class.
//
// A grafted read has two ways to fail and they mean opposite things, so
// they may not share an error:
//
//   - THE SOURCE WAS UNREACHABLE. A GET failed, a token expired, a
//     federation was down. Nothing is wrong with the volume or with the
//     source; the read is worth trying again, and probably worth trying
//     again in a moment. That is an ordinary I/O error and stays one.
//   - THE SOURCE ANSWERED AND THE BYTES WERE NOT THE PUBLISHED BYTES.
//     The block did not hash to the identity the signed generation names,
//     or the object is now shorter than the generation says it is. The
//     volume and the source now disagree about what a file contains, and
//     RETRYING CANNOT HELP: the next read of the same range returns the
//     same wrong bytes, because the source really has changed. The only
//     way forward is `pelfs graft --refresh`, which republishes the
//     generation against what the source holds now.
//
// Before this class existed both arrived at a caller as an untyped error
// and at the kernel as EIO — which is what put "returning EIO for an
// unrecognized error" in the log of a mount whose graft source had
// legitimately been republished, the one failure in this system that is
// neither damage nor a bug and most needs to say so.
//
// The message is unchanged, deliberately: it already names the graft, the
// object, the range, both hashes, what changed, and the fix, and this is
// about CLASSIFICATION rather than wording.
var (
	// ErrGraftIntegrity is what every graft-integrity failure wraps.
	// Callers test for it with errors.Is; the FUSE binding maps it to
	// EBADMSG rather than EIO so that "do not retry, the data changed"
	// is distinguishable from "the network failed" at the syscall
	// boundary too (internal/rawfuse, errStatus).
	ErrGraftIntegrity = errors.New("genfs: grafted bytes are not the bytes this generation published")
)

// GraftIntegrityKind says which of the two integrity failures happened.
// Both are the same class — the source no longer holds what was
// published — and they are kept apart because they carry different
// evidence: one has two hashes to print, the other has two lengths.
type GraftIntegrityKind uint8

const (
	// GraftHashMismatch: the block arrived at full length and hashed to
	// something else. This is the one that a whole-object digest
	// recorded at graft time could not have caught on a ranged read.
	GraftHashMismatch GraftIntegrityKind = iota + 1
	// GraftShortObject: the source object is shorter than the index says,
	// so the range the generation named does not exist any more.
	GraftShortObject
)

func (k GraftIntegrityKind) String() string {
	switch k {
	case GraftHashMismatch:
		return "hash-mismatch"
	case GraftShortObject:
		return "short-object"
	default:
		return "unknown"
	}
}

// GraftIntegrityError is one graft-integrity failure with everything a
// report, a log line or an fsck finding needs, so that a caller does not
// have to parse the message to learn which graft or which object.
type GraftIntegrityError struct {
	Kind GraftIntegrityKind
	// Graft is the path in this volume the graft is mounted at, and
	// Source the foreign prefix it reads from.
	Graft, Source string
	// Key is the source object, Off/Length the range that was asked for.
	Key         string
	Off, Length int64
	// Want is the identity the signed generation names; Got the identity
	// the bytes that arrived actually have. Empty for GraftShortObject,
	// where the bytes never arrived in full — Have carries the length
	// instead.
	Want, Got string
	// Have is how many bytes came back, for GraftShortObject.
	Have int64
	// Msg is the human sentence, kept whole so the wording lives in one
	// place and this type stays a carrier rather than a formatter.
	Msg string
}

func (e *GraftIntegrityError) Error() string { return e.Msg }

// Unwrap makes errors.Is(err, ErrGraftIntegrity) true for every one of
// these, which is the whole point of the class: a caller asks the
// question once and does not enumerate kinds.
func (e *GraftIntegrityError) Unwrap() error { return ErrGraftIntegrity }

// graftHashMismatch builds the failure for a block that arrived whole and
// hashed to something else.
func graftHashMismatch(e *graftEntry, key string, off, length int64, got, want string) error {
	return &GraftIntegrityError{
		Kind: GraftHashMismatch, Graft: e.sb.Path, Source: e.sb.Source,
		Key: key, Off: off, Length: length, Want: want, Got: got,
		Msg: fmt.Sprintf("genfs: graft %s: %s/%s [%d,+%d) hashes to %s, the generation "+
			"says %s — the graft source has changed since it was spidered, so these bytes are "+
			"NOT what this volume published; run `pelfs graft --refresh %s` to republish it",
			e.sb.Path, e.sb.Source, key, off, length, got, want, e.sb.Path),
	}
}

// graftShortObject builds the failure for a source object that no longer
// covers the range the generation named.
func graftShortObject(e *graftEntry, key string, off, length, have int64) error {
	return &GraftIntegrityError{
		Kind: GraftShortObject, Graft: e.sb.Path, Source: e.sb.Source,
		Key: key, Off: off, Length: length, Have: have,
		Msg: fmt.Sprintf("genfs: graft %s: read %s/%s [%d,+%d): short read (%d bytes) — "+
			"the source object has changed or been truncated; `pelfs graft --refresh %s` republishes it",
			e.sb.Path, e.sb.Source, key, off, length, have, e.sb.Path),
	}
}
