import { useState } from "react";
import type { BrowseState } from "../api/types";
import { publish } from "../api/control";
import {
  GLYPH,
  LEASE_WORDS,
  PUBLISH_HINT,
  describe,
  publishState,
} from "../durability";

/**
 * The durability panel: the two things a file manager cannot give.
 *
 * It is the same panel cmd/pelfs/browse.html renders, driven by the same
 * `/events` snapshot and using the vocabulary in ../durability.ts -- see that
 * file for why there is exactly one vocabulary, and
 * internal/webui/durability_test.go for what fails if the two ever drift. The
 * reason it is HERE as well as there is that a user of the file manager must
 * not have to go and look: the whole trap this milestone exists to close is a
 * finished drag-and-drop that nobody publishes, and a link is not a
 * substitute for the sentence.
 */
export function Durability({
  state,
  token,
  onNotice,
}: {
  state: BrowseState | null;
  token: string;
  onNotice: (text: string) => void;
}) {
  const [status, setStatus] = useState<string>("");
  const line = describe(state);
  const pstate = publishState(state);
  const job = state?.publish;

  async function onPublish() {
    setStatus("asking pelfs to publish…");
    try {
      const out = await publish(token);
      if (out.kind === "busy") {
        // 409 is not an error the user caused: another publish already holds
        // the overlay's lock. Say which one, and keep watching it.
        setStatus(
          `a publish is already running${out.job ? ` (job ${out.job})` : ""} — watching it`,
        );
      } else if (out.kind === "refused") {
        setStatus(`publish refused: ${out.why}`);
      } else {
        setStatus("");
      }
    } catch (e) {
      setStatus(`publish refused: ${String(e)}`);
    }
  }

  // The job's own state wins over the click's, because it is the truth: the
  // click only says the request was accepted.
  let jobText = status;
  if (job && job.state === "running") {
    jobText = "publishing… — the seal freezes the overlay, so uploads resume in a moment";
  } else if (job && job.state === "failed") {
    jobText = `publish failed: ${job.error}`;
  } else if (job && job.state === "done" && !status) {
    jobText = `published: ${job.summary}`;
  }

  return (
    <section className="pelfs-durability" data-testid="pelfs-durability-panel">
      <p
        className={`pelfs-durability__line pelfs-durability__line--${line.state}`}
        data-testid="durability"
        data-durability={line.state}
      >
        {line.glyph ? (
          <span className={`pelfs-glyph pelfs-glyph--${line.state}`} aria-hidden="true">
            {line.glyph}
          </span>
        ) : null}
        {line.text}
      </p>

      {/* The legend is ALWAYS visible, not a tooltip: it is what makes the
          two glyphs mean something to somebody seeing them for the first
          time, and a tooltip is invisible on a touch screen and to anybody
          who does not think to hover. */}
      <div className="pelfs-legend" data-testid="durability-legend">
        <span>
          <span className="pelfs-glyph pelfs-glyph--staged" data-testid="glyph-staged">
            {GLYPH.staged}
          </span>
          on this machine only
        </span>
        <span>
          <span className="pelfs-glyph pelfs-glyph--sending" data-testid="glyph-sending">
            {GLYPH.sending}
          </span>
          sending
        </span>
        <span>
          <span className="pelfs-glyph pelfs-glyph--published" data-testid="glyph-published">
            {GLYPH.published}
          </span>
          in the federation
        </span>
      </div>

      <div className="pelfs-publishrow">
        <button
          type="button"
          className="pelfs-button"
          data-testid="publish-button"
          data-publish-state={pstate}
          disabled={pstate !== "ready"}
          onClick={() => {
            onNotice("");
            void onPublish();
          }}
        >
          Publish now
        </button>
        <span data-testid="publish-hint" className="pelfs-muted">
          {PUBLISH_HINT[pstate]}
        </span>
        {/* NO LINK TO THE CONNECTION PAGE, deliberately, until the wiring
            pass decides where each surface lives: M1 serves its page at "/",
            which is also where this bundle would be mounted, and a link that
            reloads this app would spend nothing but the user's session (the
            bootstrap token is single-use). When both pages have addresses,
            one anchor goes here. */}
      </div>
      <p data-testid="publish-status" data-job-state={job?.state ?? "none"} className="pelfs-muted">
        {jobText}
      </p>

      {state && LEASE_WORDS[state.lease] ? (
        <p className="pelfs-banner pelfs-banner--bad" data-testid="lease-banner">
          {LEASE_WORDS[state.lease]}
        </p>
      ) : null}
    </section>
  );
}
