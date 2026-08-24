import { CONNECT, MODE, expect, openConnect, openPelfs, test } from "./pelfs";

/**
 * THE TWO SURFACES HAVE TWO ADDRESSES, AND EACH ONE CAN BE REACHED FROM THE
 * OTHER.
 *
 * The wiring pass had one decision to make and this file is what pins it:
 *
 *   `/`         the file manager. It is what `pelfs browse` promises — "browse
 *               and upload files" — so it is what the address the terminal
 *               prints leads to.
 *   `/connect`  the connection page: the credential desk (U7/U8), the
 *               generated Cyberduck profile, the federation-login cards (U13),
 *               and its own copy of the durability panel.
 *
 * WHY THE PAIR OF ANCHORS IS WORTH A TEST rather than being obviously fine: a
 * link from a single-page app to another page on the same origin is the one
 * navigation that can silently cost the user their session. The token lives in
 * `sessionStorage`, which is scoped to the ORIGIN and survives a same-origin
 * navigation — but the BOOTSTRAP token is single-use and already spent, so a
 * link that somehow sent the page back through the exchange would land the
 * user on "this launch link was already used" with no way back. So the round
 * trip is driven for real, in both directions, and the session is asserted to
 * be alive at the end of it.
 */
test.describe("the two addresses", () => {
  test.skip(
    MODE !== "browse",
    "/connect is cmd/pelfs/browse.html; internal/webui's test server serves the bundle only",
  );

  test("the file manager links to the connection page, and the link works", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);
    const link = page.getByTestId("connect-link");
    await expect(link).toBeVisible();
    await expect(link).toHaveAttribute("href", CONNECT);

    await link.click();
    // M1's page, by its own ids: the credential desk and the WebDAV URL.
    await expect(page.getByTestId("connect-another-program")).toBeVisible();
    await expect(page.getByTestId("add-program-form")).toBeVisible();
    // The session came with us — a page with no credential shows its own
    // error instead of the volume's name.
    await expect(page.getByTestId("session-error")).toHaveCount(0);
    await expect(page.getByTestId("volume")).toBeVisible();
  });

  test("the connection page links back, and the file manager is still alive", async ({
    page,
    session,
  }) => {
    await openConnect(page, session);
    const back = page.getByTestId("app-link");
    await expect(back).toBeVisible();
    await expect(back).toHaveAttribute("href", "/");

    await back.click();
    // Not just the shell: the data plane answered, which is what proves the
    // session survived the round trip rather than the page merely rendering.
    await expect(page.getByTestId("pelfs-shell")).toBeVisible();
    await expect(page.getByTestId("durability")).toBeVisible();
    await expect(page.getByTestId("pelfs-error")).toHaveCount(0);
    await expect(page.getByTestId("session-error")).toHaveCount(0);
  });

  test("both pages answer the same question in the same words", async ({ page, session }) => {
    // ONE VOCABULARY, ASSERTED ACROSS THE WIRE rather than across two source
    // files. internal/webui/durability_test.go reads both sources and compares
    // their string literals, which catches a reworded phrase; it cannot catch
    // a panel that renders the right words from the wrong state. This does:
    // the same volume, the same moment, two renderings.
    await openPelfs(page, session);
    const app = page.getByTestId("durability");
    await expect(app).toHaveAttribute("data-durability", "published");
    const appText = ((await app.textContent()) ?? "").replace(/\s+/g, " ").trim();

    await openConnect(page, session);
    const connect = page.getByTestId("durability");
    await expect(connect).toHaveAttribute("data-durability", "published");
    const connectText = ((await connect.textContent()) ?? "").replace(/\s+/g, " ").trim();

    expect(appText, "the two panels must not word one state two ways").toBe(connectText);
    // Neither page carries a glyph legend any more -- each glyph appears
    // beside its own words in the sentence, so the legend was a second copy of
    // the text and it is deleted on both surfaces rather than on one.
    await expect(page.getByTestId("durability-legend")).toHaveCount(0);
  });

  test("the connection page says where the file manager is, in one short line", async ({
    page,
    session,
  }) => {
    // M1's page carried one honest sentence about its own limits: "this page
    // does not browse files". That was the whole answer when nothing did. Now
    // something does, and half an answer is worse than the old whole one --
    // so the sentence has to name the address.
    //
    // AND IT HAS TO BE SHORT. This lede grew into a 180-word paragraph that
    // explained WebDAV, the profile's stability, the per-session
    // authorization, the password's lifetime and what is written to disk --
    // "The connect page text is HORRIBLE. It overly explains, a wall of text
    // for a page that can just configure CyberDuck." A word budget is a crude
    // assertion and it is the only one that catches the thing that actually
    // went wrong, which is length.
    await openConnect(page, session);
    const blurb = page.getByTestId("connect-blurb");
    await expect(blurb).toContainText("does not browse files");
    await expect(blurb.locator('a[href="/"]')).toHaveCount(1);
    const words = ((await blurb.textContent()) ?? "").trim().split(/\s+/).length;
    expect(words, "the lede is a line, not an essay").toBeLessThan(55);

    // The concrete thing, named and linked. A user who has never heard the
    // word "Cyberduck" cannot act on "connect another program"; a link can be
    // clicked. It is an ordinary anchor -- tests/loopback.spec.ts is what
    // proves the page still FETCHES nothing off this machine.
    const duck = page.getByTestId("cyberduck-link");
    await expect(duck).toHaveAttribute("href", "https://cyberduck.io/");
    await expect(duck).toHaveAttribute("rel", /noopener/);

    // And the whole page's prose is now beside its controls rather than above
    // them: the paragraph that began "The Cyberduck profile is the same file
    // every session" is gone, and nothing on the page says it.
    const main = page.locator("main");
    await expect(main).not.toContainText("the same file every session");
    await expect(main).not.toContainText("Nothing handed out here can publish");
  });

  test("the footer is at the bottom of the viewport, on a short page", async ({
    page,
    session,
  }) => {
    // "The footer is not at the bottom of the browser on /connect." This page
    // is three panels on a good day and one on a read-only session, so normal
    // flow left the status line halfway up the viewport with grey ground under
    // it. Geometry, not a class name: how it is pinned is a design choice and
    // where it lands is not.
    await openConnect(page, session);
    await expect(page.getByTestId("connect-another-program")).toBeVisible();
    const footer = page.locator("footer");
    const box = (await footer.boundingBox())!;
    const viewport = page.viewportSize()!;
    expect(
      viewport.height - (box.y + box.height),
      "the footer's bottom edge is the viewport's",
    ).toBeLessThan(2);
    // And the page is not scrolled to get there: a footer that is only at the
    // bottom because the document is taller than the window is the bug.
    expect(await page.evaluate(() => window.scrollY)).toBe(0);
  });

  test("the wordmark goes home", async ({ page, session }) => {
    // "I feel like I should be able to click the 'pelfs' / Pelican logo at the
    // upper-left to go back to 'home'." Every web page in the world has taught
    // that gesture, and this one did not answer it.
    await openConnect(page, session);
    const home = page.getByTestId("brand-home");
    await expect(home).toHaveAttribute("href", "/");
    // It has to LOOK clickable where it navigates, and the cheapest honest
    // check of that is the cursor the browser resolves for it.
    expect(await home.evaluate((el) => getComputedStyle(el).cursor)).toBe("pointer");
    // The mark and the word are both inside the anchor, which is what makes
    // the target the size a person aims at.
    await expect(home.locator("img")).toHaveCount(1);
    await expect(home).toContainText("pelfs");

    await home.click();
    await expect(page.getByTestId("pelfs-shell")).toBeVisible();
    await expect(page.getByTestId("session-error")).toHaveCount(0);
  });
});
