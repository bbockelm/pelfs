package superblock

import "fmt"

// Validate checks the invariants a superblock must hold BEFORE it becomes
// a branch head. It is a WRITER's check, deliberately: every writer calls
// it on the document it is about to flip, and no reader calls it.
//
// Not in Decode, and the reason is the one document that legitimately
// breaks the rule below. The superblock BACKUP that rides in the last pack
// states the packs its seal has cut so far inline — they exist in no
// manifest, because the seal has not written one yet — while carrying its
// parent's manifest refs for everything older; its pack set is the union
// of the two. That is sound for a disaster-recovery artifact nothing
// mounts, and it is exactly what must not be true of a branch head, where
// two lists that can disagree is the failure this rejects. Decode reads
// both kinds of document and cannot tell them apart; a writer always can.
//
// One rule today. Others belong here as they are found: a rule enforced by
// a single `if` at a single writer is a rule the OTHER writer does not
// have, which is how publish and repack came to disagree about the
// condemned ledgers (condemn.go).
func (sb *Superblock) Validate() error {
	// A generation states its pack set ONE way (see the Manifests field).
	// With both populated a reader prefers the manifest and silently
	// ignores a non-empty inline list, so the two can disagree about what
	// the volume references while only one of them is swept for.
	if len(sb.PackList) > 0 && len(sb.Manifests) > 0 {
		return fmt.Errorf("superblock: generation %d states its pack set twice — %d inline pack entries "+
			"and %d manifest ref(s); a generation that records manifests must not also write PackList",
			sb.Generation, len(sb.PackList), len(sb.Manifests))
	}
	return nil
}
