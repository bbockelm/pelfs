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
    // And the legend, which is what makes the glyphs mean anything.
    await expect(page.getByTestId("durability-legend")).toContainText("on this machine only");
    await expect(page.getByTestId("durability-legend")).toContainText("in the federation");
  });

  test("the connection page says where the file manager is", async ({ page, session }) => {
    // M1's page carried one honest sentence about its own limits: "this page
    // does not browse files". That was the whole answer when nothing did. Now
    // something does, and half an answer is worse than the old whole one --
    // so the sentence has to name the address.
    await openConnect(page, session);
    const blurb = page.getByTestId("connect-blurb");
    await expect(blurb).toContainText("does not browse files");
    await expect(blurb.locator('a[href="/"]')).toHaveCount(1);
  });
});
