import type { SessionResponse } from "./types";

/**
 * The credential half of the app, and it is deliberately the same protocol
 * cmd/pelfs/browse.html implements -- the bootstrap token arrives in the URL
 * FRAGMENT, is exchanged exactly once for a header-borne session token, and
 * the fragment is wiped out of the address bar before anything else runs.
 *
 * Why sessionStorage and not a cookie, restated where the code is because it
 * is the single most load-bearing decision in the threat model: a cookie for
 * 127.0.0.1 is sent to EVERY other service on 127.0.0.1 the browser is made
 * to contact, because cookies have no port isolation at all (RFC 6265bis
 * 8.5). sessionStorage is scoped to the ORIGIN, port included, and dies with
 * the tab. localStorage would survive the tab, which is a credential
 * outliving the process that minted it -- for a token that is revoked by the
 * process exiting, that is only a way to look valid while being useless.
 */
export const SESSION_KEY = "pelfs.session";
export const SESSION_HEADER = "X-Pelfs-Session";

export type SessionOutcome =
  | { ok: true; token: string }
  | { ok: false; reason: string };

/** Reads the bootstrap token out of the fragment, and removes it from view. */
export function takeBootstrapFromFragment(): string | null {
  const m = /(?:^|[#&])bt=([A-Za-z0-9._~%-]+)/.exec(location.hash);
  if (!m) return null;
  // replaceState, not a redirect: it drops the fragment from this tab's
  // history entry as well as from the address bar. A fragment is never sent
  // in a request line and never appears in a Referer, so history is the only
  // place it lingers.
  history.replaceState(null, "", location.pathname + location.search);
  return decodeURIComponent(m[1]);
}

/**
 * Establishes the session: the stored token if this tab already has one,
 * otherwise one exchange of the bootstrap token.
 *
 * The bootstrap token is single-use by construction (internal/browsesession
 * clears it on success), so a second tab, a reload of a spent link, or a
 * refresh after the 120-second TTV all land in the `ok: false` branch -- and
 * that has to be VISIBLE, because the alternative is a page that looks broken
 * for no stated reason.
 */
export async function establishSession(base = "/api/v1"): Promise<SessionOutcome> {
  const bootstrap = takeBootstrapFromFragment();
  let stored: string | null = null;
  try {
    stored = sessionStorage.getItem(SESSION_KEY);
  } catch {
    // A browser with storage denied is a browser this app cannot hold a
    // credential in. Say so rather than half-working.
    return {
      ok: false,
      reason:
        "this browser will not let the page store a session for this tab, " +
        "and pelfs has no cookie to fall back on. Allow site data for 127.0.0.1, or use `pelfs mount`.",
    };
  }
  if (stored) return { ok: true, token: stored };
  if (!bootstrap) {
    return {
      ok: false,
      reason:
        "this tab has no pelfs session. The launch link is single-use, so a new tab cannot " +
        "inherit one: start `pelfs browse` again to get a fresh link.",
    };
  }

  let res: Response;
  try {
    res = await fetch(`${base}/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bootstrap }),
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
  } catch (e) {
    return { ok: false, reason: `pelfs browse did not answer (${String(e)}). Is it still running?` };
  }
  if (!res.ok) {
    return {
      ok: false,
      reason:
        "this launch link has expired or was already used (it is good for one open, for two " +
        "minutes). Run `pelfs browse` again for a new one.",
    };
  }
  const body = (await res.json()) as SessionResponse;
  if (!body.session) return { ok: false, reason: "the server minted no session token" };
  try {
    sessionStorage.setItem(SESSION_KEY, body.session);
  } catch {
    /* the token still works for this page load */
  }
  return { ok: true, token: body.session };
}
