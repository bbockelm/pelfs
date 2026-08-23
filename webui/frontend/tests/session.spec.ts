import {
  BASE,
  MODE,
  SESSION_KEY,
  apiHeaders,
  expect,
  openPelfs,
  test,
  testHook,
  watchSetCookie,
} from "./pelfs";

/**
 * THE CREDENTIAL, IN A REAL BROWSER.
 *
 * Every assertion here is one a Go test cannot make. "We never call
 * http.SetCookie" is provable in Go; "no cookie exists in the browser after a
 * whole session" is not, because the interesting cookie is the one some other
 * service on 127.0.0.1 set -- cookies have NO port isolation (RFC 6265bis
 * 8.5), which is the entire reason this design has none of its own.
 *
 * Likewise "the token is in sessionStorage": what matters is that it is NOT
 * in localStorage, because localStorage outlives the tab while the token is
 * revoked by `pelfs browse` exiting. A credential that outlives its issuer
 * only looks valid.
 */
test.describe("the session credential", () => {
  test("no Set-Cookie on any response, and document.cookie is empty after a full session", async ({
    page,
    session,
    playwright,
  }) => {
    const cookies = watchSetCookie(page);
    const request = await playwright.request.newContext();

    await openPelfs(page, session);
    await expect(page.getByTestId("pelfs-shell")).toBeVisible();

    // A whole session, not just a load: state changes, a publish, a stream.
    if (MODE === "browse") {
      await testHook(request, session, { staged_files: 1, staged_bytes: 4096 });
      await expect(page.getByTestId("durability")).toHaveAttribute("data-durability", "staged");
      await page.getByTestId("publish-button").click();
      await expect(page.getByTestId("publish-status")).toHaveAttribute("data-job-state", "done");
      await testHook(request, session, { reset: true });
    }

    expect(cookies, `the server set a cookie: ${cookies.join(", ")}`).toHaveLength(0);
    // The browser's own answer, which is the one that counts.
    expect(await page.evaluate(() => document.cookie)).toBe("");
    expect(await page.context().cookies()).toHaveLength(0);
    await request.dispose();
  });

  test("the token is in sessionStorage, and localStorage is untouched", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);
    await expect(page.getByTestId("pelfs-shell")).toBeVisible();

    const storage = await page.evaluate((key) => {
      const local: string[] = [];
      for (let i = 0; i < localStorage.length; i++) local.push(localStorage.key(i) ?? "");
      return { session: sessionStorage.getItem(key), localKeys: local };
    }, SESSION_KEY);

    expect(storage.session, "the session token belongs in sessionStorage").toBeTruthy();
    expect(
      storage.localKeys,
      `localStorage must stay empty; found ${storage.localKeys.join(", ")}`,
    ).toHaveLength(0);
  });

  test("the bootstrap token is single-use: a second exchange fails, visibly", async ({
    page,
    playwright,
  }) => {
    // The worker fixture already spent it -- that IS the first use. What this
    // asserts is that the second one cannot succeed, from the server and then
    // from the page.
    const bootstrap = process.env.PELFS_WEBUI_BOOTSTRAP!;
    const request = await playwright.request.newContext();
    const res = await request.post(new URL("api/v1/session", BASE).toString(), {
      headers: apiHeaders(),
      data: { bootstrap },
    });
    expect(res.status(), "a spent bootstrap token must not mint a second session").toBe(401);
    // And the refusal says nothing about WHICH wall was hit: "wrong",
    // "expired" and "already used" are one answer, because the only caller
    // who benefits from the difference is one iterating.
    expect(await res.text()).not.toContain("already");
    await request.dispose();

    // Now the same thing where a person would see it: a fresh tab, the spent
    // link, and no stored session.
    await page.goto(`/#bt=${encodeURIComponent(bootstrap)}`);
    const failure = page.getByTestId("session-error");
    await expect(failure).toBeVisible();
    await expect(failure).toContainText(/expired|already used|single-use|no pelfs session/i);
  });

  test("the bootstrap token never stays in the address bar", async ({ page, session }) => {
    // A fragment is never sent in a request line and never appears in a
    // Referer, so the only places it lingers are this tab's history entry and
    // the address bar -- and replaceState removes both. The token here is
    // already spent, which is the point: the page must strip it whether or
    // not it needed it.
    await page.addInitScript(
      ([key, value]) => {
        try {
          sessionStorage.setItem(key, value);
        } catch {
          /* asserted elsewhere */
        }
      },
      [SESSION_KEY, session] as [string, string],
    );
    await page.goto("/#bt=this-token-must-not-survive");
    await expect(page.getByTestId("pelfs-shell")).toBeVisible();
    expect(await page.evaluate(() => location.hash)).toBe("");
    expect(page.url()).not.toContain("this-token-must-not-survive");
  });

  test("an API request without the session header is refused", async ({ playwright }) => {
    const request = await playwright.request.newContext();
    // Including on a GET. The credential is required on every method, which is
    // what closes net/http.CrossOriginProtection's documented "safe methods
    // are always allowed" gap.
    const res = await request.get(new URL("api/v1/info", BASE).toString(), {
      headers: apiHeaders(),
    });
    expect(res.status()).toBe(401);
    await request.dispose();
  });
});
