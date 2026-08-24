// THE BROWSER HALF OF scripts/oauth-browser-docker.sh.
//
// It is not a mock of a browser and it is not a browser's "role played by
// curl": it launches Chromium, navigates to the authorization URL Cyberduck
// itself printed, clicks the Authorize button with a real input event, and
// then ASSERTS ON THE BYTES CHROMIUM PUT ON THE WIRE at each step -- which is
// the whole point, because the two bugs this gate was written for were both
// "the browser sends something curl did not".
//
// It writes one `ck <0|1> <name>` line per check to stdout, which the shell
// probe reads and reports in the house format, plus `## ` diagnostic lines.
// Exit status is the number of failing checks, so the caller does not have to
// parse anything to know.
//
// Modes:
//   consent <authorize-url>   drive one full authorization to the callback
//   refusals <origin> <client-id> <redirect> <challenge>
//                             the refusal pages, as a browser renders them

import http from "node:http";

import { chromium } from "playwright-core";

const CHROME = process.env.PELFS_CHROMIUM ?? "/usr/bin/chromium";

let fails = 0;
function ck(ok, name) {
  if (!ok) fails++;
  console.log(`ck ${ok ? 0 : 1} ${name}`);
}
function note(...a) {
  console.log("## " + a.join(" "));
}

/**
 * launch is the one place the browser's flags live.
 *
 * `--no-sandbox`: a container with no user namespaces cannot start the zygote.
 * `--host-resolver-rules` is deliberately NOT set -- everything here is a
 * literal 127.0.0.1, and a resolver rule would be a way for a mistake in a
 * URL to be silently corrected into a passing test.
 */
async function launch() {
  return chromium.launch({
    executablePath: CHROME,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
}

/**
 * record attaches the listeners this gate's assertions read.
 *
 * `request` is recorded with allHeaders(), which is the post-launch header set
 * -- the browser-attached `sec-fetch-*` and `origin` included. headers() alone
 * would give the pre-flight set and would have shown neither of the two
 * headers this gate exists to check. A failed request cannot answer
 * allHeaders(), so those fall back to headers() and are marked.
 */
function record(page) {
  const seen = { requests: [], responses: [], failed: [], console: [], offLoopback: [] };
  page.on("request", async (r) => {
    let h;
    let full = true;
    try {
      h = await r.allHeaders();
    } catch {
      h = r.headers();
      full = false;
    }
    const rec = { method: r.method(), url: r.url(), headers: h, full, type: r.resourceType() };
    seen.requests.push(rec);
    if (!/^http:\/\/127\.0\.0\.1:/.test(r.url()) && !r.url().startsWith("about:")) {
      seen.offLoopback.push(rec);
    }
  });
  page.on("response", (r) => seen.responses.push({ status: r.status(), url: r.url(), headers: r.headers() }));
  page.on("requestfailed", (r) => seen.failed.push({ url: r.url(), why: r.failure()?.errorText }));
  page.on("console", (m) => seen.console.push(`${m.type()}: ${m.text()}`));
  return seen;
}

const lastOf = (list, pred) => [...list].reverse().find(pred);

// ------------------------------------------------------------------ consent

async function consent(url) {
  const origin = new URL(url).origin;
  const browser = await launch();
  const page = await (await browser.newContext()).newPage();
  const seen = record(page);

  // 1. THE NAVIGATION CYBERDUCK OPENS. A URL handed to the platform opener
  //    arrives as a top-level navigation with `Sec-Fetch-Site: none` and NO
  //    Origin header at all, which is the case internal/httpguard's
  //    SurfaceNavigation exists for.
  await page.goto(url, { waitUntil: "load" });
  const nav = seen.requests.find((r) => r.method === "GET" && r.url === url);
  const navRes = seen.responses.find((r) => r.url === url);
  ck(navRes?.status === 200, `browser:authorize-get   ${navRes?.status} on the navigation Cyberduck opened`);
  ck(nav?.headers["sec-fetch-site"] === "none",
    `browser:sec-fetch-none  sec-fetch-site=${nav?.headers["sec-fetch-site"]} (an externally opened URL)`);
  ck(!("origin" in (nav?.headers ?? {})),
    `browser:no-origin-on-get a GET navigation sends no Origin (${nav?.headers?.origin ?? "absent"})`);

  // The response header that decides bug 1: `no-referrer` here is what made
  // the form POST below send `Origin: null`.
  const rp = navRes?.headers["referrer-policy"];
  ck(rp === "same-origin", `browser:referrer-policy  the consent page serves Referrer-Policy: ${rp}`);

  const ticketed = await page.locator('input[name="consent_ticket"]').count();
  ck(ticketed === 1, `browser:consent-rendered a consent form with a ticket`);

  // WHAT THE SCREEN SAYS, which is three facts and two buttons. The callback
  // row and the paragraph of reassurance under them were deleted -- "useless
  // over-explanation", and a loopback URL with a port in it is not something
  // a person can act on -- so their absence is asserted here rather than
  // trusted to stay absent.
  const consentText = await page.locator("body").innerText();
  ck(!/sends the authorization to/i.test(consentText) && !/one thing standing/i.test(consentText),
    `page:consent-is-terse    no callback row and no essay on the consent screen`);
  ck(/Cyberduck/.test(consentText) && /pelican:\/\//.test(consentText) && /read/i.test(consentText),
    `page:consent-names-ask   the screen names the program, the volume and the scope`);

  // 2. THE CLICK. Playwright's click dispatches a trusted input event, so
  //    this is the "one real user gesture" internal/localoauth's consent
  //    page is built around -- not form.submit(), which `script-src 'none'`
  //    makes impossible anyway.
  await page.locator("button.go").click();
  await page.waitForLoadState("load").catch(() => {});
  await page.waitForTimeout(1000);

  const post = lastOf(seen.requests, (r) => r.method === "POST");
  const postRes = lastOf(seen.responses, (r) => r.url.endsWith("/oauth/authorize"));
  note("the consent POST, as Chromium sent it:");
  for (const k of Object.keys(post?.headers ?? {}).sort()) note(`    ${k}: ${post.headers[k]}`);

  // BUG 1a. The header that was `null` and answered 403.
  ck(post?.headers.origin === origin,
    `browser:origin-on-post   the consent POST carries Origin: ${post?.headers.origin}`);
  ck(post?.headers["sec-fetch-site"] === "same-origin",
    `browser:sec-fetch-post   sec-fetch-site=${post?.headers["sec-fetch-site"]} on the form POST`);
  ck(post?.headers["content-type"]?.startsWith("application/x-www-form-urlencoded"),
    `browser:form-encoded     ${post?.headers["content-type"]}`);
  ck(postRes?.status === 200, `browser:consent-200      the POST answered ${postRes?.status}, not a refusal`);

  // BUG 3, AND THE ONE A USER REPORTED IN THEIR OWN WORDS: "when I click
  // Authorize, nothing happens in the browser. I'd expect a 'success' type
  // page." The POST used to 303 to Cyberduck's loopback listener, which
  // answers by closing the connection -- so the browser's last act in the
  // flow was to land on ERR_EMPTY_RESPONSE at the moment everything worked.
  // The tab must now be sitting on a pelfs page that says so.
  const landed = page.url();
  const success = await page.locator("body").innerText();
  ck(landed.startsWith(origin),
    `browser:lands-on-pelfs  the tab ended on ${landed.slice(0, 60)}, not a dead callback`);
  ck(/Connected/i.test(success) && /close this tab/i.test(success),
    `browser:success-page     the page tells the user the program is connected`);

  // BUG 1b. The redirect a `form-action 'self'` policy blocked. A CSP
  // violation is reported to the console and NOWHERE ELSE -- no status code,
  // no failed response the server can see -- which is exactly why no
  // server-side test could have caught it.
  const csp = seen.console.filter((m) => /Content Security Policy/i.test(m));
  ck(csp.length === 0, `browser:no-csp-violation ${csp.length ? csp[0].slice(0, 110) : "the page reported none"}`);
  // Blocked requests TO PELFS only. The request to the client's own callback
  // is expected to fail: Cyberduck's loopback HttpServer answers a captured
  // authorization by closing the connection rather than by writing a
  // response, so `ERR_EMPTY_RESPONSE` there is the flow working. (The
  // curl-driven gates say the same thing about curl's "empty reply".)
  const blocked = seen.failed.filter((f) => f.url.startsWith(origin));
  ck(blocked.length === 0,
    `browser:no-blocked-req   ${blocked.length ? blocked[0].why + " " + blocked[0].url : "pelfs blocked nothing"}`);

  // 3. WHERE THE BROWSER ENDED UP: the client's own loopback listener, with
  //    the code on the query. This is the byte Cyberduck is waiting for.
  const cb = lastOf(seen.requests, (r) => /\/pelfs\/oauth\/callback\?/.test(r.url));
  const hasCode = /[?&]code=[A-Za-z0-9._~-]+/.test(cb?.url ?? "");
  ck(hasCode, `browser:code-delivered  the authorization reached the client's callback`);
  // AND IT GOT THERE FROM A FRAME, not from a navigation the user was
  // dumped on. That is the mechanism the success page above depends on: if
  // `frame-src` stops naming the callback, this request never happens and
  // Cyberduck waits forever on a callback that a CSP silently blocked --
  // which is precisely the failure mode this whole gate exists for.
  ck(cb?.type === "document" && landed.startsWith(origin),
    `browser:frame-delivered  the code was delivered from the page, not by leaving it`);

  // And it reached it with NO Referer, which is the property
  // `Referrer-Policy: same-origin` keeps that plain `no-referrer` was chosen
  // for: the callback is a different origin (a different port IS a different
  // origin), so nothing about the authorization URL travels to it. The
  // client_id and the code are on that URL.
  ck(cb !== undefined && !("referer" in cb.headers),
    `browser:no-referer-out   the callback request carries no Referer (${cb?.headers?.referer ?? "absent"})`);

  // 4. NOTHING LEFT LOOPBACK. The same rule the app bundle is held to
  //    (webui/frontend/tests/loopback.spec.ts), applied to the consent page,
  //    which is hand-written HTML with `default-src 'none'` over it.
  ck(seen.offLoopback.length === 0,
    `browser:no-beacon        ${seen.offLoopback.length ? seen.offLoopback[0].url : "zero requests left 127.0.0.1"}`);

  // 5. PRESSING IT TWICE. "If I click it twice, I get an error" was the
  //    second half of the report, and reproducing it faithfully in a browser
  //    means being precise about which "twice" it was.
  //
  //    A RELOAD of the success page is the one that hurts: the browser
  //    re-POSTs the SAME consent ticket. That used to be indistinguishable
  //    from a forged POST and got the forged POST's page -- "this
  //    authorization screen is no longer live" -- shown to somebody who had
  //    just successfully connected. It must now say what the first press
  //    already did, and it must NOT re-deliver the code, because a code
  //    presented twice is what revokes the grant.
  const callbacksBefore = seen.requests.filter((r) => /\/pelfs\/oauth\/callback\?/.test(r.url)).length;
  await page.reload({ waitUntil: "load" }).catch(() => {});
  await page.waitForTimeout(500);
  const twice = await page.locator("body").innerText();
  const twiceRes = lastOf(seen.responses, (r) => r.url.endsWith("/oauth/authorize"));
  const twicePost = lastOf(seen.requests, (r) => r.method === "POST" && r.url.endsWith("/oauth/authorize"));
  ck(twicePost !== undefined, `browser:resubmits        the reload re-POSTed the consent form`);
  ck(twiceRes?.status === 200 && /Already connected/i.test(twice),
    `browser:second-press     re-submitting answered ${twiceRes?.status} ` +
    `${JSON.stringify(twice.split("\n")[0])}`);
  const callbacksAfter = seen.requests.filter((r) => /\/pelfs\/oauth\/callback\?/.test(r.url)).length;
  ck(callbacksAfter === callbacksBefore,
    `browser:no-redelivery    the second press sent nothing to the client (${callbacksBefore} -> ${callbacksAfter})`);

  //    AND THE OTHER "twice", which is Back and press again. That is a NEW
  //    screen with a new ticket, and it must be -- consent is never
  //    remembered at /authorize, so a client asking a second time asks a
  //    second human. What it must not be is an error.
  await page.goBack({ waitUntil: "load" }).catch(() => {});
  await page.waitForTimeout(300);
  const backText = await page.locator("body").innerText();
  const backForm = await page.locator('input[name="consent_ticket"]').count();
  ck(backForm === 1 && !/no longer live/i.test(backText),
    `browser:back-is-a-screen going back offers a fresh consent screen, not a refusal`);

  await browser.close();
  return cb?.url ?? "";
}

// ----------------------------------------------------------------- refusals

/**
 * refusals renders the pages a REFUSED authorization shows, in a browser,
 * because "whatever the cause, a refusal at /oauth/authorize must explain
 * itself on the page in terms a user can act on" is the other half of the
 * report this gate came from -- the user was left with the three words
 * "origin refused" and no next step.
 */
async function refusals(origin, clientID, redirect, challenge) {
  const browser = await launch();
  const page = await (await browser.newContext()).newPage();
  const seen = record(page);
  const q = (o) =>
    origin + "/oauth/authorize?" + new URLSearchParams({ response_type: "code", ...o }).toString();

  // A callback off by one port. The page must name BOTH ports, because
  // "that address is not the one in this profile" with no numbers in it is
  // not something a user can act on.
  const off = redirect.replace(/:(\d+)\//, (_, p) => `:${Number(p) + 1}/`);
  await page.goto(q({ client_id: clientID, redirect_uri: off, scope: "pelfs.read", code_challenge: challenge, code_challenge_method: "S256" }));
  const body = await page.locator("body").innerText();
  const wantPort = new URL(redirect).port;
  const gotPort = new URL(off).port;
  ck(body.includes(wantPort) && body.includes(gotPort),
    `page:names-both-ports    the refusal names port ${wantPort} and port ${gotPort}`);
  ck(!body.includes(off) && !body.includes(clientID),
    `page:echoes-nothing      neither the sent URL nor the client id is echoed`);
  ck((await page.locator("h1").count()) === 1 && body.length > 120,
    `page:is-a-page           a rendered explanation, not a line of text/plain`);

  // An unknown client. Same rule: a page, and nothing of the request on it.
  await page.goto(q({ client_id: "not-a-client-at-all", redirect_uri: redirect, scope: "pelfs.read", code_challenge: challenge, code_challenge_method: "S256" }));
  const unknown = await page.locator("body").innerText();
  ck(unknown.includes("pelfs") && !unknown.includes("not-a-client-at-all"),
    `page:unknown-client      explained, with no echo of the identifier`);

  // AND THE GUARD'S OWN REFUSAL, which is the one the bug report actually
  // quoted. A form POST from a page on ANOTHER LOOPBACK PORT is refused by
  // internal/httpguard before internal/localoauth ever sees it -- by F3 a
  // different port is same-SITE, and CrossOriginProtection rejects an unsafe
  // method from same-site. On a document navigation that refusal must be a
  // page, not the three words "origin refused" that the person who reported
  // this was left with.
  //
  // The attacker page has to be served by a server of its own, for the reason
  // scripts/webui-playwright.sh gives at length: a document built with
  // setContent has an opaque origin and no URL, and its form submission is
  // not the case this is about.
  const evil = http.createServer((_q, s) => {
    s.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    s.end(
      `<!doctype html><meta charset=utf-8><title>a page the user merely visited</title>` +
      `<form id=f method=post action="${origin}/oauth/authorize">` +
      `<input name=consent_ticket value=x><input name=decision value=allow></form>`,
    );
  });
  await new Promise((r) => evil.listen(0, "127.0.0.1", r));
  const evilURL = `http://127.0.0.1:${evil.address().port}/`;
  await page.goto(evilURL);
  await page.evaluate(() => document.getElementById("f").submit());
  await page.waitForURL(/\/oauth\/authorize$/, { timeout: 15_000 }).catch(() => {});
  const refused = await page.locator("body").innerText();
  const refusedRes = lastOf(seen.responses, (r) => r.url === origin + "/oauth/authorize");
  evil.close();
  ck(refusedRes?.status === 403, `page:guard-403           a same-site form POST answered ${refusedRes?.status}`);
  ck(/refused/i.test(refused) && refused.length > 120,
    `page:guard-refusal       the transport refusal renders as a page: ${JSON.stringify(refused.slice(0, 60))}`);

  ck(seen.offLoopback.length === 0,
    `page:no-beacon           ${seen.offLoopback.length ? seen.offLoopback[0].url : "zero requests left 127.0.0.1"}`);
  await browser.close();
}

// --------------------------------------------------------------------- main

const [mode, ...rest] = process.argv.slice(2);
try {
  if (mode === "consent") await consent(rest[0]);
  else if (mode === "refusals") await refusals(rest[0], rest[1], rest[2], rest[3]);
  else {
    console.error(`unknown mode ${mode}`);
    process.exit(2);
  }
} catch (e) {
  console.log(`ck 1 browser:driver-crashed ${String(e).slice(0, 200)}`);
  fails++;
}
process.exit(fails);
