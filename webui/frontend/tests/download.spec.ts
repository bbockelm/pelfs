import { BASE, MODE, expect, openPelfs, resetHooks, test, testHook } from "./pelfs";

/**
 * THE TICKETED DOWNLOAD, which is the one route with no credential at all --
 * and that is the design, not an omission.
 *
 * An `<a href>` or a `window.location` cannot set a request header, so a
 * download authorized by the session token would have to be authorized by an
 * AMBIENT credential on a GET. An ambient-credential GET is exactly what a
 * cross-origin `<img>`, `<script>`, `<iframe>` or top-level navigation can
 * trigger, and what DNS rebinding turned into arbitrary RPC in CVE-2018-5702,
 * where a custom header WAS the CSRF defence. So the authority is a ticket:
 * 256 bits, ONE use, 30 seconds, minted by an authenticated call.
 *
 * The properties worth a browser: that the redemption really does work with
 * no credential of any kind, and that the URL sitting in the browser's
 * download history is already spent by the time it is written there.
 */
test.describe("the download ticket", () => {
  test.skip(
    MODE !== "browse",
    "M1 registers a synthetic download source only under --test-hooks; " +
      "the embed server's own ticket flow is covered in filemanager.spec.ts",
  );

  test.afterEach(async ({ playwright, session }) => {
    const request = await playwright.request.newContext();
    await resetHooks(request, session);
    await request.dispose();
  });

  test("mint with the session, redeem with nothing, and the replay 404s", async ({
    page,
    session,
    playwright,
  }) => {
    const request = await playwright.request.newContext();
    const body = "pelfs synthetic download body\n";
    await testHook(request, session, { download_body: body });
    await openPelfs(page, session);

    // Minting is the AUTHENTICATED half: this is where a real implementation
    // checks that the session may read the path. The /d/ route does no
    // checking at all, because it has no principal to check with.
    const minted = await page.evaluate(
      async ([header, token]) => {
        const r = await fetch("/api/v1/download", {
          method: "POST",
          headers: { "Content-Type": "application/json", [header]: token },
          body: JSON.stringify({ path: "/example.dat" }),
        });
        return { status: r.status, body: (await r.json()) as { url?: string; ttl?: string } };
      },
      ["X-Pelfs-Session", session] as [string, string],
    );
    expect(minted.status).toBe(200);
    expect(minted.body.url, "the ticket is a path, not a query parameter").toMatch(/^\/d\/[\w.~-]+$/);
    const url = new URL(minted.body.url!, BASE).toString();

    // Redeemed with NO headers whatsoever: no session, no origin, no cookie.
    // This request context has never seen the page.
    const bare = await playwright.request.newContext();
    const got = await bare.get(url);
    expect(got.status(), "a ticket must be redeemable with no credential").toBe(200);
    expect(await got.text()).toBe(body);

    // Three headers that are not optional, because the volume holds files the
    // user did not write: serving one as text/html from this origin would run
    // its script with the app's own session in reach.
    const headers = got.headers();
    expect(headers["content-type"]).toBe("application/octet-stream");
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["content-disposition"]).toContain("attachment");

    // The replay. This is what makes the spent URL in the download history
    // harmless -- and 404, not 401 or 403, because "unknown", "spent" and
    // "expired" are one answer and it says nothing about which.
    const again = await bare.get(url);
    expect(again.status(), "a ticket must be single-use").toBe(404);
    await bare.dispose();
    await request.dispose();
  });

  test("an invented ticket is a 404, and says nothing else", async ({ playwright }) => {
    const bare = await playwright.request.newContext();
    const res = await bare.get(new URL("d/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", BASE).toString());
    expect(res.status()).toBe(404);
    await bare.dispose();
  });

  test("a path the session may not read is 403, not the bytes", async ({
    page,
    session,
    playwright,
  }) => {
    // "you cannot" and "there is nothing" are different answers and the user
    // acts differently on each, so the source distinguishes them even though
    // the ticket layer does not.
    const request = await playwright.request.newContext();
    await testHook(request, session, { download_body: "never served\n" });
    await openPelfs(page, session);

    const minted = await page.evaluate(
      async ([header, token]) => {
        const r = await fetch("/api/v1/download", {
          method: "POST",
          headers: { "Content-Type": "application/json", [header]: token },
          body: JSON.stringify({ path: "/forbidden" }),
        });
        return (await r.json()) as { url?: string };
      },
      ["X-Pelfs-Session", session] as [string, string],
    );
    const bare = await playwright.request.newContext();
    const res = await bare.get(new URL(minted.url!, BASE).toString());
    expect(res.status()).toBe(403);
    await bare.dispose();
    await request.dispose();
  });

  test("a download does not navigate the page away from itself", async ({
    page,
    session,
    playwright,
  }) => {
    // A download that replaced the page would lose the session (it lives in
    // this tab's sessionStorage) and the durability panel with it. The
    // attachment disposition is what keeps the tab where it is.
    const request = await playwright.request.newContext();
    await testHook(request, session, { download_body: "bytes\n" });
    await openPelfs(page, session);
    const before = page.url();

    const download = page.waitForEvent("download");
    await page.evaluate(
      async ([header, token]) => {
        const r = await fetch("/api/v1/download", {
          method: "POST",
          headers: { "Content-Type": "application/json", [header]: token },
          body: JSON.stringify({ path: "/example.dat" }),
        });
        const { url } = (await r.json()) as { url: string };
        const a = document.createElement("a");
        a.href = url;
        a.rel = "noreferrer";
        document.body.appendChild(a);
        a.click();
        a.remove();
      },
      ["X-Pelfs-Session", session] as [string, string],
    );
    await download;
    expect(page.url()).toBe(before);
    await expect(page.getByTestId("durability")).toBeVisible();
    await request.dispose();
  });
});
