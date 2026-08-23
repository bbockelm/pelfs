import { expect, test } from "@playwright/test";

// The DNS-rebinding and cross-origin harness, proven end to end.
//
// The full battery is here: a fetch at /api/v1/files, a <form method=POST>
// submission, an <img src> at a download path, an <iframe> of /, and a
// PROPFIND via fetch at /dav/. The first two tests are the ones that make the
// rest mean anything -- they prove the browser really is sending the
// attacker's hostname, so what follows is testing the control rather than a
// misconfigured flag.
//
// The mechanism is Chromium's --host-resolver-rules (playwright.config.ts, the
// cross-origin project): "MAP attacker.test 127.0.0.1" resolves an arbitrary
// hostname to loopback with no change to /etc/hosts and no root. The page's
// own requests then carry `Host: attacker.test:PORT`, which is exactly the
// header the Host allowlist must reject with 421 Misdirected Request.
const attackerHost = process.env.PELFS_WEBUI_ATTACKER_HOST || "attacker.test";
const mode = process.env.PELFS_WEBUI_MODE ?? "embed";

function attackerURL(base: string, path = "/") {
  const u = new URL(base);
  u.hostname = attackerHost;
  u.pathname = path;
  return u.toString();
}

/**
 * The page the attacker actually serves, on its own port and its own origin.
 *
 * It is NOT this server under the mapped hostname, and the difference is the
 * whole validity of the battery below: `pelfs browse` answers a rebound Host
 * with 421, and every response it sends carries
 * `Content-Security-Policy: default-src 'none'; form-action 'none'`. A fetch
 * or a form submission from THAT document is stopped by our own CSP before it
 * is stopped by the control the test is about, so the test would pass while
 * measuring nothing. scripts/webui-playwright.sh starts a five-line static
 * server for this; without it these specs skip rather than pretend.
 */
const attackerPage = process.env.PELFS_WEBUI_ATTACKER_URL;

test("the rebinding vector is real: the browser sends the attacker's hostname", async ({ page }) => {
  test.skip(
    mode !== "embed",
    "/__host exists only in internal/webui's test server; in browse mode the guard's 421 is the assertion below",
  );
  const base = process.env.PELFS_WEBUI_URL!;
  const port = new URL(base).port;

  await page.goto(attackerURL(base));

  // The fetch must come from INSIDE the page, not from page.request: an
  // APIRequestContext request is made by Playwright's own Node process, which
  // knows nothing about --host-resolver-rules, so "attacker.test" would not
  // resolve at all. Only the browser's network stack applies the mapping, and
  // only the browser writes the Host header this test is about.
  const body = await page.evaluate(async () => {
    const r = await fetch("/__host");
    return (await r.json()) as { host: string };
  });

  expect(body.host).toBe(`${attackerHost}:${port}`);
});

test("a rebound request is answered 421", async ({ page }) => {
  test.skip(
    mode !== "browse",
    "needs the real server: internal/webui's test server has no Host allowlist, by design",
  );
  const base = process.env.PELFS_WEBUI_URL!;

  // Navigating to the attacker name IS the rebinding attack: same address,
  // different name, and the browser has no way to know the difference. The
  // server does, because the Host header changed.
  const res = await page.goto(attackerURL(base));
  expect(res?.status(), "the Host allowlist must reject a hostname that is not ours").toBe(421);

  // And the rejection must not echo the attacker's hostname back into the
  // page, which would make the 421 body itself a reflection vector.
  const text = await page.content();
  expect(text).not.toContain(attackerHost);
});

test("a cross-origin page cannot read the server's responses", async ({ page }) => {
  test.skip(!attackerPage, "needs the harness's attacker origin; see attackerPage above");
  const base = process.env.PELFS_WEBUI_URL!;
  // A page on the attacker origin fetching the app's own origin is a
  // genuinely cross-site request. No CORS headers are served on any surface,
  // so the browser refuses to hand the response to the page. Asserting the
  // BROWSER's refusal is the whole reason this suite exists -- a Go test
  // cannot prove it.
  await page.goto(attackerPage!);
  const result = await page.evaluate(async (target) => {
    try {
      const r = await fetch(target, { mode: "cors" });
      return { ok: r.ok, status: r.status };
    } catch (e) {
      return { blocked: String(e) };
    }
  }, base);
  expect(result).toHaveProperty("blocked");
});

// ---------------------------------------------------------------------------
// The battery. Each of these is a way a page the user merely VISITS can reach
// a loopback server, and each is refused by a different control.
// ---------------------------------------------------------------------------

test("a cross-origin form POST is refused: a form needs no CORS permission to be SENT", async ({
  page,
}) => {
  test.skip(mode !== "browse", "needs the real guard; the embed server has none, by design");
  test.skip(!attackerPage, "needs the harness's attacker origin; see attackerPage above");
  const base = process.env.PELFS_WEBUI_URL!;
  await page.goto(attackerPage!);

  // This is the case CORS does NOT cover. A form submission is a top-level
  // navigation the browser performs without asking anyone's permission, and
  // if the server authorized it by an ambient credential it would be a
  // completed publish. The credential is not ambient, and the request carries
  // `Origin: http://attacker.test:PORT`, which is not this server's origin.
  const target = new URL("/api/v1/publish", base).toString();
  const answer = page.waitForResponse((r) => r.url() === target);
  await page.evaluate((action) => {
    const f = document.createElement("form");
    f.method = "POST";
    f.action = action;
    // text/plain is one of the three types a form can send, and the reason
    // the API requires application/json: a form can never produce it.
    f.enctype = "text/plain";
    document.body.appendChild(f);
    f.submit();
  }, target);

  const res = await answer;
  expect(res.status(), "a cross-origin form POST must not be accepted").toBe(403);
  // And the refusal must not echo the attacker's hostname back into a page.
  expect(await res.text()).not.toContain(attackerHost);
});

test("an <img> at the download path loads nothing", async ({ page }) => {
  test.skip(!attackerPage, "needs the harness's attacker origin; see attackerPage above");
  const base = process.env.PELFS_WEBUI_URL!;
  await page.goto(attackerPage!);

  // <img> is the classic ambient-credential GET. The download surface takes a
  // single-use ticket in the PATH and no credential at all, so an attacker
  // who cannot guess 256 bits gets a 404 -- and even a hit would arrive as
  // `Content-Disposition: attachment` with `nosniff`, which is not an image.
  const outcome = await page.evaluate((src) => {
    return new Promise<string>((resolve) => {
      const img = new Image();
      img.onload = () => resolve("loaded");
      img.onerror = () => resolve("error");
      img.src = src;
    });
  }, new URL("/d/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", base).toString());
  expect(outcome).toBe("error");
});

test("the app cannot be framed", async ({ page }) => {
  test.skip(!attackerPage, "needs the harness's attacker origin; see attackerPage above");
  test.skip(
    mode !== "browse",
    "the framing headers come from internal/httpguard, which the embed test server does not run",
  );
  const base = process.env.PELFS_WEBUI_URL!;
  await page.goto(attackerPage!);

  // Framing is how a page that cannot READ a response can still make a user
  // CLICK inside one. Two headers refuse it, and both are asserted rather
  // than assumed: a browser that honoured neither would frame it happily.
  const res = await page.request.get(base);
  const headers = res.headers();
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");

  const readable = await page.evaluate((src) => {
    return new Promise<boolean>((resolve) => {
      const f = document.createElement("iframe");
      f.src = src;
      f.onload = () => {
        try {
          resolve(!!f.contentDocument && !!f.contentDocument.body.innerHTML);
        } catch {
          resolve(false);
        }
      };
      f.onerror = () => resolve(false);
      document.body.appendChild(f);
    });
  }, base);
  expect(readable, "the attacker page must not be able to read a framed pelfs").toBeFalsy();
});

test("a PROPFIND from a page never leaves the browser", async ({ page }) => {
  test.skip(!attackerPage, "needs the harness's attacker origin; see attackerPage above");
  const base = process.env.PELFS_WEBUI_URL!;
  await page.goto(attackerPage!);

  // PROPFIND is not a CORS-safelisted method, so the browser must preflight
  // it -- and this server answers no Access-Control-Allow-* header on any
  // surface, so the preflight can never be satisfied and the real request is
  // never sent. That is what makes the whole WebDAV write surface (work item
  // U6) unreachable from a page BY CONSTRUCTION rather than by a check
  // somebody has to remember to write.
  const result = await page.evaluate(async (target) => {
    try {
      const r = await fetch(target, { method: "PROPFIND", headers: { Depth: "1" } });
      return { ok: r.ok, status: r.status };
    } catch (e) {
      return { blocked: String(e) };
    }
  }, new URL("/dav/", base).toString());
  expect(result).toHaveProperty("blocked");
});
