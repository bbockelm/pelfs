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
 * It used to open lowercase, mid-sentence, and it repeated two facts the app
 * bar already carries: the session's mode ("read-only.", which is a chip three
 * inches to the right) and the generation ("(generation 5)", which is beside
 * the branch). The owner's verdict was "strangely capitalized and repeats
 * things elsewhere in the UI", and both halves were true. So: a capitalised
 * sentence, no mode, no generation. Where the volume stands is the app bar's
 * job; whether the user's bytes are safe is this line's, and it is the only
 * line on either surface that answers it.
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
  if (s.mode === "read-only" || (s.staged_files === 0 && s.dirty_nodes === 0)) {
    return {
      state: "published",
      glyph: GLYPH.published,
      text: "Everything here is in the federation.",
    };
  }
  const sending =
    s.upload_backlog > 0 ? ` ${GLYPH.sending} Sending ${bytes(s.upload_backlog)}.` : "";
  // The idle clause is not decoration: it is the promise that closing this
  // tab publishes rather than abandoning. Said only when the server says
  // idle sealing is on for this session, and in cmd/pelfs/browse.html's
  // words, because the two surfaces have one vocabulary.
  const idle =
    s.idle_seal_s && s.idle_seal_s > 0 ? `, or ${secs(s.idle_seal_s)} after this tab closes` : "";
  return {
    state: "staged",
    glyph: GLYPH.staged,
    text:
      `${s.staged_files} file${s.staged_files === 1 ? "" : "s"} (${bytes(s.staged_bytes)}) ` +
      `on this machine only. Next publish in ${secs(s.next_publish_s)}${idle}.${sending}`,
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
  if (s.staged_files === 0 && s.dirty_nodes === 0) return "nothing";
  return "ready";
}

export const PUBLISH_HINT: Record<PublishState, string> = {
  ready: "",
  connecting: "(waiting for the volume)",
  // Nothing: the line above is the whole answer, and it is the server's.
  failed: "",
  "read-only": "(read-only session — restart with --rw to publish)",
  running: "(publishing — this holds the overlay, so writes wait)",
  switching: "(switching branches — this holds the overlay, so writes wait)",
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
