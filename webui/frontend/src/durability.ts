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
 * The wiring pass gave both surfaces addresses -- `/` is this app, `/connect`
 * is browse.html -- and did NOT make either panel a link to the other. A link
 * would be the wrong reconciliation: the sentence is what closes the trap, and
 * a user who has to navigate to read it is a user who does not read it. The
 * authority both panels quote is the SERVER's snapshot, not each other, so
 * there is one answer with two renderings rather than two answers.
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
  failed: "✗", // ✗ cross: the volume never opened, so none of the above is known
} as const;

export type Durability = "unknown" | "staged" | "published" | "failed";

/**
 * The lead-in on a failed open, and the ONLY words this file adds to one.
 *
 * Everything after it is the server's own sentence, verbatim: it names the
 * state directory and the next step (wait out the branch lease, or point at
 * another state dir), and a page that paraphrased or truncated it would take
 * away the one thing the reader can act on.
 */
export const OPEN_FAILED = "pelfs could not open this volume.";

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

/**
 * The one-line answer to "is my data in the federation yet", AND NOTHING ELSE.
 *
 * IT IS THE ONLY LINE. A running seal used to be said twice -- this countdown,
 * and a second paragraph under it reading "publishing… — the seal freezes the
 * overlay, so uploads resume in a moment". The owner's verdict was "This data
 * could all be on the same line!", so the countdown clause BECOMES the
 * publishing clause while a seal runs and the paragraph under it renders
 * nothing (ui/Durability.tsx).
 *
 * THE IDLE CLAUSE WENT WITH THAT EDIT. ", or 30s after this tab closes" was
 * true and was not worth the width. The behaviour is untouched --
 * cmd/pelfs/idleseal.go still seals a session whose last tab went away -- and
 * a publish that happens that way still says so when it lands.
 *
 * What did NOT get shortened away is the distinction. Three glyphs, three
 * characters, and "on this machine only" never wearing the check --
 * internal/webui/durability_test.go and tests/durability.spec.ts both fail if
 * that erodes.
 */
export function describe(s: BrowseState | null): DurabilityLine {
  // A FAILED OPEN IS NOT A SLOW ONE, and this line is where the difference
  // used to be lost. Every phase that was not "ready" rendered as "Reading
  // the overlay…", so the volume refusing to open -- a branch lease left
  // behind by a `--rw` session that did not exit cleanly is the ordinary way
  // in -- looked exactly like a volume that was about to open. That is the
  // report: "whenever I start read-write, I just get a page that says
  // 'reading the overlay…'. Never seems to progress."
  //
  // The server now SERVES the reason rather than racing the browser with it
  // (cmd/pelfs/browsefail.go): the listener stays up, and `error` carries a
  // whole sentence -- what refused, where this session's state directory is,
  // and what to do next. So this renders that sentence, unedited, and stops
  // claiming progress.
  if (s && s.phase === "failed") {
    return {
      state: "failed",
      glyph: GLYPH.failed,
      text: s.error ? `${OPEN_FAILED}\n${s.error}` : OPEN_FAILED,
    };
  }
  if (!s || s.phase !== "ready") {
    return { state: "unknown", glyph: "", text: "Reading the overlay…" };
  }
  // A read-only session and a writable one with nothing staged are the same
  // answer to the only question this line asks, so they are the same sentence.
  // The difference between them is a mode chip and a publish control, both of
  // which are elsewhere and neither of which is durability.
  //
  // `unpublished` AND NOT THE COUNTERS. This used to test the staged-file and
  // dirty-inode counts for zero, which is a re-derivation of the seal's
  // predicate -- and it was the wrong one: a rename writes no bytes and no
  // inode row, only namespace edges, so the page told a user who had just
  // renamed a file that everything was in the federation while the seal knew
  // otherwise. The server now answers the predicate itself
  // (cmd/pelfs/browse.go), so there is one definition of "there is something
  // to publish" rather than two.
  if (s.mode === "read-only" || !s.unpublished) {
    return {
      state: "published",
      glyph: GLYPH.published,
      text: "Everything here is in the federation.",
    };
  }
  const sending =
    s.upload_backlog > 0 ? ` ${GLYPH.sending} Sending ${bytes(s.upload_backlog)}.` : "";
  // A seal in flight REPLACES the countdown rather than standing under it: a
  // countdown to a publish that is already running is two answers to one
  // question, and they are the pair the owner asked to collapse.
  const when =
    s.publish && s.publish.state === "running" && s.publish.reason !== "branch"
      ? "Publishing now."
      : `Next publish in ${secs(s.next_publish_s)}.`;
  // WHAT IS UNPUBLISHED IS NOT ALWAYS BYTES, and the sentence has to survive
  // that. A rename, a delete, a mkdir, a hardlink stage namespace and nothing
  // else, so the counted sentence would read "0 files (0 B) on this machine
  // only" -- a line that reports the size of the change as zero while claiming
  // there is one, which is the same ambiguity in a new place. The short
  // sentence is the honest one: what the reader has to know is that it is here
  // and not there, and the count was never the point.
  const what =
    s.staged_files > 0
      ? `${s.staged_files} file${s.staged_files === 1 ? "" : "s"} (${bytes(s.staged_bytes)}) ` +
        `on this machine only.`
      : `Changes on this machine only.`;
  return {
    state: "staged",
    glyph: GLYPH.staged,
    text: `${what} ${when}${sending}`,
  };
}

export type PublishState =
  | "ready"
  | "connecting"
  | "failed"
  | "read-only"
  | "running"
  | "switching"
  | "nothing";

/**
 * `switching` and `running` are the SAME job slot and not the same event.
 *
 * `POST /api/v1/branch` reports its progress as a publish job with
 * `reason: "branch"` (cmd/pelfs/browsebranch.go), because a switch and a seal
 * both hold the session lock for their whole duration and a second slot would
 * only be a second name for the same queue. Rendering it as "publishing…"
 * would tell the user their bytes are being written to the federation while
 * the session is reopening an overlay on another branch head, which is the
 * one thing this panel exists not to do.
 */
export function publishState(s: BrowseState | null): PublishState {
  if (!s) return "connecting";
  if (s.phase === "failed") return "failed";
  if (s.phase !== "ready") return "connecting";
  if (s.mode === "read-only") return "read-only";
  if (s.publish && s.publish.state === "running") {
    return s.publish.reason === "branch" ? "switching" : "running";
  }
  // The SAME predicate the line above uses, and the server's rather than this
  // page's: a button reading "Nothing to publish" over a session that would
  // publish a rename is the bug this field exists to end.
  if (!s.unpublished) return "nothing";
  return "ready";
}

/**
 * ONE CONTROL, WEARING ITS OWN STATE.
 *
 * There used to be a hint beside the button as well as the button: a disabled
 * control reading "Publish now" with "(nothing to publish)" next to it says one
 * thing twice, and the owner said so -- "duplicate info". So the label IS the
 * state, and there is nothing beside it.
 *
 * An empty label means NO BUTTON AT ALL: a failed open has no volume to publish
 * to, and a read-only session gets READ_ONLY_HINT where the control would be.
 */
export const PUBLISH_LABEL: Record<PublishState, string> = {
  ready: "Publish now",
  nothing: "Nothing to publish",
  running: "Publishing",
  // A branch switch takes the same job slot and is NOT a publish, so it does
  // not borrow the word: the button says what is actually happening.
  switching: "Switching branches",
  connecting: "Waiting for the volume",
  failed: "",
  "read-only": "",
};

/** The one session that gets a sentence instead of a control. */
export const READ_ONLY_HINT = "(read-only session — restart with --rw to publish)";

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
