import type { BrowseState } from "./api/types";

/**
 * The durability vocabulary, in ONE place, and it is M1's vocabulary.
 *
 * cmd/pelfs/browse.html already renders this panel, and a file manager that
 * rendered a SECOND, subtly different account of what is published would be
 * worse than one that rendered none: the whole value of the panel is that
 * "on this machine" and "in the federation" are unmistakably different, and
 * two surfaces disagreeing about which is which destroys exactly that. So the
 * app is a second CLIENT of the same `/events` snapshot, rendering the same
 * three glyphs and the same sentences, and internal/webui/durability_test.go
 * fails if the two drift apart.
 *
 * THE GLYPHS ARE THREE DIFFERENT CHARACTERS ON PURPOSE. The failure mode the
 * whole panel exists to prevent is a green check on the staged row: a file
 * that looks uploaded and is not in the federation is the worst possible
 * ambiguity for this audience, because the user's next action is to close the
 * laptop and tell a collaborator the data is there. Colour alone would not do
 * it -- roughly one man in twelve cannot use it -- so the shape carries the
 * meaning and the colour only reinforces it.
 */
export const GLYPH = {
  staged: "●", // ● filled dot: on this machine only
  sending: "◔", // ◔ moving arc: packs in flight
  published: "✓", // ✓ check: named by a generation in the federation
} as const;

export type Durability = "unknown" | "staged" | "published";

export function bytes(n: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

export function secs(s: number): string {
  if (s <= 0) return "any moment now";
  const m = Math.floor(s / 60);
  const r = s % 60;
  return m > 0 ? `${m}m${String(r).padStart(2, "0")}s` : `${r}s`;
}

export type DurabilityLine = {
  state: Durability;
  glyph: string;
  /** The sentence, without the glyph. */
  text: string;
};

/** The one-line answer to "is my data in the federation yet". */
export function describe(s: BrowseState | null): DurabilityLine {
  if (!s || s.phase !== "ready") {
    return { state: "unknown", glyph: "", text: "reading the overlay…" };
  }
  if (s.mode === "read-only") {
    return {
      state: "published",
      glyph: GLYPH.published,
      text: `read-only. everything here is in the federation (generation ${s.generation}).`,
    };
  }
  if (s.staged_files === 0 && s.dirty_nodes === 0) {
    return {
      state: "published",
      glyph: GLYPH.published,
      text: `nothing staged. everything here is in the federation (generation ${s.generation}).`,
    };
  }
  const sending =
    s.upload_backlog > 0 ? ` ${GLYPH.sending} sending ${bytes(s.upload_backlog)}.` : "";
  return {
    state: "staged",
    glyph: GLYPH.staged,
    text:
      `${s.staged_files} file${s.staged_files === 1 ? "" : "s"} (${bytes(s.staged_bytes)}) ` +
      `on this machine only — next automatic publish in ${secs(s.next_publish_s)} ` +
      `(sooner under write pressure).${sending}`,
  };
}

export type PublishState = "ready" | "connecting" | "read-only" | "running" | "nothing";

export function publishState(s: BrowseState | null): PublishState {
  if (!s || s.phase !== "ready") return "connecting";
  if (s.mode === "read-only") return "read-only";
  if (s.publish && s.publish.state === "running") return "running";
  if (s.staged_files === 0 && s.dirty_nodes === 0) return "nothing";
  return "ready";
}

export const PUBLISH_HINT: Record<PublishState, string> = {
  ready: "",
  connecting: "(waiting for the volume)",
  "read-only": "(read-only session — restart with --rw to publish)",
  running: "(publishing — this holds the overlay, so writes wait)",
  nothing: "(nothing to publish)",
};

/**
 * A lease this session no longer holds means everything the user does from
 * here is going to fail at the seal, so it is a banner the moment it is known
 * rather than a surprise at exit. The four values are the control socket's
 * own; "none" and "held" get no banner.
 */
export const LEASE_WORDS: Record<string, string> = {
  stale:
    "This session's branch lease is past its TTL — the laptop may have slept. Another writer " +
    "was entitled to take the branch during that window; a publish now will re-check and may refuse.",
  interrupted:
    "This session's lease object has vanished. pelfs will resolve it against the branch head " +
    "at the next publish.",
  lost:
    "Another client has taken this branch. This session can no longer publish; its staged work " +
    "is still on this machine and is not lost.",
};
