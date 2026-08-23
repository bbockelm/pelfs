import { test as base, expect, type APIRequestContext, type Page } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * The suite's shared machinery, and the two constraints that shape all of it.
 *
 * CONSTRAINT 1: THERE IS EXACTLY ONE BOOTSTRAP TOKEN PER SERVER, AND IT IS
 * SINGLE-USE. `pelfs browse` mints one 32-byte token, prints it in the launch
 * URL's fragment, and internal/browsesession clears it the moment it is
 * exchanged. Playwright gives every test a FRESH BROWSER CONTEXT, so a suite
 * that let each test do the exchange would have exactly one passing test and
 * a file of "this launch link was already used". So the exchange happens ONCE
 * per worker, from Node, and every test seeds the resulting session token
 * into sessionStorage with an init script -- which is precisely what a reload
 * of a real tab does, since the token lives there and the page prefers it to
 * the fragment.
 *
 * The single-use property itself is not lost by doing it this way: it is
 * asserted directly, in session.spec.ts, by taking the spent token back to
 * the browser and watching the page say so.
 *
 * CONSTRAINT 2: NO FIXED SLEEPS, ANYWHERE. Not one setTimeout, not one
 * waitForTimeout. `retries: 0` is only honest if the suite is deterministic,
 * and the way to be deterministic against a live SSE stream is to poll an
 * assertion until it holds (expect(...).toPass) rather than to guess how long
 * something takes on a loaded CI runner.
 */

export const MODE = process.env.PELFS_WEBUI_MODE ?? "embed";
export const BASE = process.env.PELFS_WEBUI_URL ?? "";
export const ORIGIN = BASE ? new URL(BASE).origin : "";
export const SESSION_KEY = "pelfs.session";
export const SESSION_HEADER = "X-Pelfs-Session";

/**
 * The headers a first-party API call must carry, and every one of them is
 * load-bearing (internal/httpguard):
 *
 *   Origin           must EXACTLY equal "http://" + the Host it was sent to;
 *   Sec-Fetch-Site   the browser sets this on a real request, and the guard
 *                    accepts it as the provenance signal in place of Origin;
 *   Content-Type     application/json on anything that mutates, or 415;
 *   X-Pelfs-Session  on every request including GET, or 401.
 *
 * A request from Node is not a browser request, so the two the browser would
 * have set are set by hand. That the guard requires them at all is the
 * fail-CLOSED direction of net/http.CrossOriginProtection's documented gap.
 */
export function apiHeaders(session?: string): Record<string, string> {
  const h: Record<string, string> = {
    "Content-Type": "application/json",
    Origin: ORIGIN,
    "Sec-Fetch-Site": "same-origin",
  };
  if (session) h[SESSION_HEADER] = session;
  return h;
}

/**
 * Where the exchanged session token is remembered, and why it has to be
 * remembered somewhere a process restart can reach.
 *
 * PLAYWRIGHT RESTARTS THE WORKER PROCESS AFTER A FAILING TEST. That is good
 * isolation and it is fatal to a worker-scoped fixture holding a SINGLE-USE
 * credential: the new worker would try to exchange a bootstrap token that the
 * old one already spent, and every test after the first genuine failure would
 * report "this launch link was already used" instead of its own result. One
 * real bug would arrive as a wall of false ones, which is exactly the noise
 * that teaches people to rerun a suite until it is green.
 *
 * So the token goes in a file keyed by the server's origin, and the fixture
 * VALIDATES a cached token before trusting it -- a stale file from a previous
 * run points at a server that is gone, and its token is refused, so the
 * fixture falls through to the exchange.
 */
function sessionCachePath(): string {
  const key = ORIGIN.replace(/[^\w]/g, "_");
  const dir = process.env.PELFS_WEBUI_SESSION_DIR || tmpdir();
  return join(dir, `pelfs-webui-session-${key}.txt`);
}

/** Reports whether a token still authenticates against this server. */
async function tokenWorks(request: APIRequestContext, token: string): Promise<boolean> {
  const res = await request.get(new URL("api/v1/info", BASE).toString(), {
    headers: apiHeaders(token),
    failOnStatusCode: false,
  });
  return res.ok();
}

/** Exchanges the single-use bootstrap token for a session token, once. */
export async function exchangeBootstrap(request: APIRequestContext): Promise<string> {
  const cache = sessionCachePath();
  try {
    const cached = readFileSync(cache, "utf8").trim();
    if (cached && (await tokenWorks(request, cached))) return cached;
  } catch {
    /* no cache yet, which is the normal first run */
  }

  const bootstrap = process.env.PELFS_WEBUI_BOOTSTRAP;
  if (!bootstrap) {
    throw new Error(
      "PELFS_WEBUI_BOOTSTRAP is not set: scripts/webui-playwright.sh hands it over, " +
        "and without it no test can authenticate to a server that mints exactly one.",
    );
  }
  const res = await request.post(new URL("api/v1/session", BASE).toString(), {
    headers: apiHeaders(),
    data: { bootstrap },
  });
  if (!res.ok()) {
    throw new Error(
      `the bootstrap exchange failed (${res.status()}): ${await res.text()}\n` +
        "The token is single-use and expires after 120 s, so a slow start is one cause.",
    );
  }
  const body = (await res.json()) as { session: string };
  try {
    writeFileSync(cache, body.session, { mode: 0o600 });
  } catch {
    /* the run still works; only a worker restart would pay for it */
  }
  return body.session;
}

type Worker = { session: string };

/**
 * `session` is worker-scoped, so the one exchange this server permits happens
 * once for the whole run.
 */
export const test = base.extend<object, Worker>({
  session: [
    async ({ playwright }, use) => {
      const request = await playwright.request.newContext();
      const token = await exchangeBootstrap(request);
      await use(token);
      await request.dispose();
    },
    { scope: "worker" },
  ],
});

export { expect };

/**
 * Opens the page with a session already in this tab, the way a reload of a
 * live tab does it.
 *
 * `addInitScript` runs before any of the page's own script, so the page finds
 * the token in sessionStorage and takes the stored-credential path instead of
 * the exchange -- which is what a second load of a real session does, because
 * the launch link is spent by then.
 */
export async function openPelfs(page: Page, session: string, path = "/") {
  await page.addInitScript(
    ([key, value]) => {
      try {
        sessionStorage.setItem(key, value);
      } catch {
        /* a context with storage denied fails the assertion, not the setup */
      }
    },
    [SESSION_KEY, session] as [string, string],
  );
  await page.goto(path);
}

/** Drives M1's `--test-hooks` route. Off by default; the harness passes it. */
export async function testHook(
  request: APIRequestContext,
  session: string,
  body: Record<string, unknown>,
) {
  const res = await request.post(new URL("api/v1/testhook", BASE).toString(), {
    headers: apiHeaders(session),
    data: body,
  });
  if (!res.ok()) {
    throw new Error(
      `POST /api/v1/testhook answered ${res.status()}: ${await res.text()}\n` +
        "The harness starts `pelfs browse --test-hooks`; without that flag the route " +
        "does not exist and these states are not reachable.",
    );
  }
  return res;
}

/** Puts every override back, so one spec cannot leak state into the next. */
export async function resetHooks(request: APIRequestContext, session: string) {
  await testHook(request, session, { reset: true });
}

/**
 * Records every request the page makes to anything that is not loopback.
 *
 * This is the standing form of a U0 measurement: the SVAR theme injects a
 * stylesheet link and a preconnect to cdn.svar.dev, and its default icon
 * callback builds a CDN URL per file extension. `fonts={false}` and
 * `icons="simple"` turn both off; this is what notices if a rebuild, a
 * version bump or a new component turns them back on. A localhost tool that
 * beacons is a localhost tool that tells a third party which files you have.
 */
export function watchOffLoopback(page: Page): string[] {
  const off: string[] = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (!u.protocol.startsWith("http")) return;
    if (u.hostname === "127.0.0.1" || u.hostname === "localhost") return;
    off.push(`${r.method()} ${u.origin}${u.pathname}`);
  });
  return off;
}

/**
 * One file card in the main view, by its path.
 *
 * `data-id` is not unique: the component puts the same id on the card in the
 * content area AND on the row in the sidebar tree (measured -- a bare
 * attribute selector resolves to two elements and Playwright's strict mode
 * refuses it, correctly). `.wx-item` is the card, which is the thing a person
 * clicks and drags, so that is what the specs mean by "the file".
 */
export function card(page: Page, id: string) {
  return page.locator(`.wx-item[data-id=":${id}"]`);
}

/** Every Set-Cookie the page ever saw. The design has none, on any surface. */
export function watchSetCookie(page: Page): string[] {
  const seen: string[] = [];
  page.on("response", (res) => {
    const headers = res.headers();
    const v = headers["set-cookie"];
    if (v) seen.push(`${res.url()} -> ${v}`);
  });
  return seen;
}
