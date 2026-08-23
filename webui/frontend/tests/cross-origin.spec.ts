import { expect, test } from "@playwright/test";

// The DNS-rebinding and cross-origin harness, proven end to end.
//
// The full battery -- a fetch at /api/v1/files, a <form method=POST>
// submission, an <img src> at a download path, an <iframe> of /, a PROPFIND
// via fetch at /dav/ -- belongs to a dedicated agent. What this file proves is
// the part that is easy to get wrong and impossible to notice: that the
// browser really is sending the attacker's hostname, so the assertions written
// later are testing the control rather than a misconfigured flag.
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
  const base = process.env.PELFS_WEBUI_URL!;
  // A page on the attacker origin fetching the app's own origin is a
  // genuinely cross-site request: different hostname, same port. No CORS
  // headers are served, so the browser refuses to hand the response to the
  // page. Asserting the BROWSER's refusal is the whole reason this suite
  // exists -- a Go test cannot prove it.
  await page.goto(attackerURL(base));
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
