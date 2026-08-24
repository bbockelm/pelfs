import { SESSION_HEADER } from "./session";
import type { BranchList } from "./types";

/**
 * THE BRANCH ROUTES, AND THE CONTRACT THIS FILE IS WRITTEN AGAINST.
 *
 * The owner asked for the branch pill to be a real control -- "I feel like I
 * should be able to click on the 'branch' pill and get a drop-down to show
 * other branches" -- and the server half is a sibling's work in progress. So
 * this is coded to an agreed contract rather than to something that answers
 * today:
 *
 *   GET  /api/v1/branches -> {"current":"main","branches":[
 *                              {"name":"main","generation":87,"head":"…",
 *                               "staged":false}, …]}
 *   POST /api/v1/branch   {"name":"dev"}
 *                         202  accepted; the switch is REPORTED ON /events,
 *                              exactly like a publish job
 *                         409  the session has staged work that switching
 *                              would strand; body carries the reason
 *                         403  a read-only session that refuses to switch
 *
 * TWO CONSEQUENCES OF "REPORTED ON /events" ARE LOAD-BEARING, and they are the
 * reason this module returns an outcome rather than a new branch:
 *
 *   1. A 202 IS NOT A SWITCH. The picker must keep showing the branch the
 *      snapshot says it is on until a frame says otherwise, or the one control
 *      whose whole job is telling you where you are becomes the one control
 *      that lies about it. ui/BranchPicker.tsx therefore renders `value` from
 *      the /events state and never from a click.
 *   2. A 404 IS NOT A FAILURE. Until the sibling lands, `list` reports
 *      "unsupported" and the pill degrades to the static fact it is today. A
 *      broken-looking dropdown on every session would be worse than no
 *      dropdown, and this is a page a user is asked to trust.
 */

function apiHeaders(token: string): Record<string, string> {
  return { "Content-Type": "application/json", [SESSION_HEADER]: token };
}

const FETCH_OPTS = {
  credentials: "omit",
  cache: "no-store",
  referrerPolicy: "no-referrer",
} as const;

export type BranchListOutcome =
  | { kind: "ok"; list: BranchList }
  /** The route is not on this server. The caller renders today's static pill. */
  | { kind: "unsupported" }
  | { kind: "error"; why: string };

export async function listBranches(token: string): Promise<BranchListOutcome> {
  let res: Response;
  try {
    res = await fetch("/api/v1/branches", {
      method: "GET",
      headers: { [SESSION_HEADER]: token },
      ...FETCH_OPTS,
    });
  } catch (e) {
    return { kind: "error", why: String(e) };
  }
  // 404 is the sibling not having landed; 405 is a router that knows the
  // path and not the verb, which is the same thing from here.
  if (res.status === 404 || res.status === 405) return { kind: "unsupported" };
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    return { kind: "error", why: body.error || `the server answered ${res.status}` };
  }
  const body = (await res.json().catch(() => null)) as BranchList | null;
  if (!body || !Array.isArray(body.branches)) {
    return { kind: "error", why: "the branch list was not a list of branches" };
  }
  return { kind: "ok", list: body };
}

export type SwitchOutcome =
  /** 202: the work started. What happened arrives on /events. */
  | { kind: "accepted" }
  /** 409: staged work would be stranded. */
  | { kind: "staged"; why: string }
  /** 403: this session will not switch. */
  | { kind: "refused"; why: string }
  | { kind: "error"; why: string };

export async function switchBranch(token: string, name: string): Promise<SwitchOutcome> {
  let res: Response;
  try {
    res = await fetch("/api/v1/branch", {
      method: "POST",
      headers: apiHeaders(token),
      body: JSON.stringify({ name }),
      ...FETCH_OPTS,
    });
  } catch (e) {
    return { kind: "error", why: String(e) };
  }
  const body = (await res.json().catch(() => ({}))) as { error?: string; reason?: string };
  const why = body.reason || body.error || "";
  if (res.status === 202) return { kind: "accepted" };
  if (res.status === 409) {
    return {
      kind: "staged",
      why: why || "this session has staged work that switching would strand",
    };
  }
  if (res.status === 403) {
    return { kind: "refused", why: why || "this session will not switch branches" };
  }
  return { kind: "error", why: why || `the server answered ${res.status}` };
}
