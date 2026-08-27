import { useEffect, useState } from "react";
import { listBranches, switchBranch } from "../api/branches";
import type { Branch } from "../api/types";

/**
 * THE BRANCH PILL, MADE A CONTROL -- "I feel like I should be able to click on
 * the 'branch' pill and get a drop-down to show other branches."
 *
 * THREE DECISIONS, and each one is the difference between a control a user can
 * trust and one they cannot.
 *
 * 1. IT IS A <select>, not a <details> menu. The state it displays is a
 *    single choice out of a list, which is what a select is; it comes with
 *    keyboard handling, a touch-screen presentation, screen-reader semantics
 *    and no JavaScript of ours in the open/close path. The disclosure pattern
 *    this file could have used is the one the caveats just got deleted for.
 *
 * 2. `value` IS THE SERVER'S ANSWER, NEVER THE CLICK. `POST /api/v1/branch`
 *    answers 202 and the switch is reported on `/events` like a publish job,
 *    so a select whose value followed the user's choice would show "dev" for
 *    as long as the switch took -- and forever, if it were refused. A
 *    controlled select with `value={current}` snaps back to the truth on its
 *    own the instant React re-renders, which is the frame after the click, and
 *    the pending line below says what was asked for. This is the same rule the
 *    durability panel follows for a publish, for the same reason.
 *
 * 3. A 404 DEGRADES TO THE STATIC FACT. The route is a sibling's work in
 *    progress; until it answers, this renders exactly what the app bar
 *    rendered before -- the branch name, as text. A control that is visibly
 *    there and visibly broken on every session would be worse than the pill,
 *    and this page is asked to be trusted about durability.
 */
export function BranchPicker({
  token,
  current,
  ready,
}: {
  token: string;
  /** The branch the /events snapshot says this session is on. */
  current: string;
  /** Whether the volume is open. There is nothing to list before that. */
  ready: boolean;
}) {
  const [branches, setBranches] = useState<Branch[] | null>(null);
  const [note, setNote] = useState("");
  const [asked, setAsked] = useState("");

  // The list, once, when the volume is open. Not on every frame: the frames
  // arrive twice a second and the set of branches is not a number that moves
  // while somebody watches it. It is re-read after an accepted switch, since
  // that is the one thing on this page that can change a generation in the
  // list.
  const [generation, setGeneration] = useState(0);
  useEffect(() => {
    if (!token || !ready) return;
    let alive = true;
    (async () => {
      const out = await listBranches(token);
      if (!alive) return;
      if (out.kind === "ok") {
        setBranches(out.list.branches);
      } else if (out.kind === "unsupported") {
        setBranches(null);
      } else {
        // A server that is there and unhappy is worth one line; it is not
        // worth replacing the fact the user came for.
        setBranches(null);
        setNote(out.why);
      }
    })();
    return () => {
      alive = false;
    };
  }, [token, ready, generation]);

  // The switch this tab asked for is over the moment the snapshot agrees.
  useEffect(() => {
    if (asked && current === asked) {
      setAsked("");
      setNote("");
      setGeneration((n) => n + 1);
    }
  }, [current, asked]);

  async function onPick(name: string) {
    if (!name || name === current) return;
    setAsked(name);
    setNote(`switching to ${name}…`);
    const out = await switchBranch(token, name);
    if (out.kind === "accepted") return; // /events says when, not this.
    setAsked("");
    setNote(out.kind === "error" ? `branch switch failed: ${out.why}` : out.why);
  }

  // THE DEGRADED FORM, and it is the same markup the app bar carried before
  // this component existed: a name, as text.
  if (!branches || branches.length === 0) {
    return (
      <span className="pelfs-fact" data-testid="branch" data-branch-control="static">
        branch <b>{current || "—"}</b>
        {note ? <span className="pelfs-branch__note"> {note}</span> : null}
      </span>
    );
  }

  // The snapshot's branch must be selectable even if the list has not caught
  // up with it, or the select would render with no matching option and the
  // browser would show the first one -- which is the exact lie decision 2 is
  // about.
  const names = branches.map((b) => b.name);
  const options: Branch[] =
    names.includes(current) && current ? branches : [{ name: current }, ...branches];

  return (
    <span className="pelfs-fact pelfs-branch" data-testid="branch" data-branch-control="select">
      <label className="pelfs-branch__label" htmlFor="pelfs-branch-select">
        branch
      </label>
      <select
        id="pelfs-branch-select"
        className="pelfs-branch__select"
        data-testid="branch-select"
        // The truth, not the click. See decision 2.
        value={current}
        // While a switch is in flight the control is not a second lever: a
        // second pick would leave two pending switches and one snapshot.
        disabled={!!asked}
        onChange={(e) => void onPick(e.target.value)}
      >
        {options.map((b) => (
          <option key={b.name} value={b.name}>
            {b.name}
            {typeof b.generation === "number" ? ` · gen ${b.generation}` : ""}
            {b.staged ? " · staged" : ""}
          </option>
        ))}
      </select>
      {note ? (
        <span className="pelfs-branch__note" data-testid="branch-note" role="status">
          {note}
        </span>
      ) : null}
    </span>
  );
}
