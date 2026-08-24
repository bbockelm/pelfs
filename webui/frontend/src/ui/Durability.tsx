import { useState } from "react";
import type { BrowseState } from "../api/types";
import { publish } from "../api/control";
import { LEASE_WORDS, PUBLISH_HINT, describe, publishState } from "../durability";

/**
 * The durability panel: the two things a file manager cannot give.
 *
 * It is the same panel cmd/pelfs/browse.html renders, driven by the same
 * `/events` snapshot and using the vocabulary in ../durability.ts -- see that
 * file for why there is exactly one vocabulary, and
 * internal/webui/durability_test.go for what fails if the two ever drift. The
 * reason it is HERE as well as there is that a user of the file manager must
 * not have to go and look: the whole trap this milestone exists to close is a
 * finished drag-and-drop that nobody publishes, and a link is not a substitute
 * for the sentence.
 *
 * TWO THINGS ABOUT ITS LAYOUT ARE DELIBERATE, AND BOTH WERE COMPLAINTS.
 *
 * THERE IS NO LEGEND. This panel used to carry, under the line, a row reading
 * "● on this machine only / ◔ sending / ✓ in the federation". It was there to
 * teach the glyphs -- but each glyph already appears beside its own words in
 * the sentence it belongs to, so the row was a second copy of the text with
 * nothing in it the sentence did not have ("Bizarre, not needed, duplicate of
 * the actual text"). The contract it was standing for is unaffected and still
 * asserted: three states, three DIFFERENT characters, staged never looking
 * like published (webui/frontend/tests/durability.spec.ts reads the glyph the
 * panel actually renders in each state and compares them).
 *
 * A READ-ONLY SESSION RENDERS NO PUBLISH CONTROL AT ALL. It used to render a
 * disabled one with "(read-only session — restart with --rw to publish)"
 * beside it, at the top of the page: a button you cannot press, under a line
 * that has already said "read-only", explaining a third time what read-only
 * means. Now the sentence is said once, where the control would have been, and
 * there is nothing to press. `pelfs browse` is read-only by DEFAULT, so this
 * is the common case, not a corner.
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
    <section
      className="pelfs-panel pelfs-panel--status"
      data-testid="pelfs-durability-panel"
      data-durability={line.state}
    >
      <div className="pelfs-status">
        <p
          className={`pelfs-status__line pelfs-status__line--${line.state}`}
          data-testid="durability"
          data-durability={line.state}
        >
          {line.glyph ? (
            <span
              className={`pelfs-glyph pelfs-glyph--${line.state}`}
              data-testid="durability-glyph"
              aria-hidden="true"
            >
              {line.glyph}
            </span>
          ) : null}
          {line.text}
        </p>

        <div className="pelfs-status__aside">
          {pstate === "read-only" ? (
            // No control, one sentence: this session cannot publish and the
            // way to change that is a flag on the command that started it.
            <span data-testid="publish-hint" className="pelfs-muted">
              {PUBLISH_HINT["read-only"]}
            </span>
          ) : (
            <>
              {PUBLISH_HINT[pstate] ? (
                <span data-testid="publish-hint" className="pelfs-muted">
                  {PUBLISH_HINT[pstate]}
                </span>
              ) : null}
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
            </>
          )}
        </div>
      </div>

      <p
        data-testid="publish-status"
        data-job-state={job?.state ?? "none"}
        // The job the panel is WATCHING, which is not always the job this tab
        // started: a 409 hands back the id of the publish that already holds
        // the overlay, and the panel follows that one. A driver asserting "the
        // second request names the job the page is watching" needs the id on
        // the element, not in the prose.
        data-job-id={job?.id ?? ""}
        className="pelfs-status__note"
      >
        {jobText}
      </p>

      {state && LEASE_WORDS[state.lease] ? (
        <p className="pelfs-note pelfs-note--bad" data-testid="lease-banner">
          {LEASE_WORDS[state.lease]}
        </p>
      ) : null}
    </section>
  );
}
