import { MODE, card, expect, openPelfs, resetHooks, test, testHook } from "./pelfs";

/**
 * DOES THIS PAGE READ AS A FILE MANAGER.
 *
 * Every other spec in this suite asserts that the app is CORRECT. This one
 * asserts that it is a tool, because the first version was correct and did not
 * look like one, and every item below is a defect somebody reported in those
 * words:
 *
 *   "there is no physical separation between the config and the file browser,
 *    hard to tell they're separate elements"
 *   "couldn't tell 'search' was a text box, no color differentiation"
 *   "there's something I guess is supposed to be a legend? ... duplicate of
 *    the actual text"
 *   "having the 'Publish now' box so prominent and up top is weird, especially
 *    since it's already labeled as read-only"
 *
 * A layout is not fully assertable and this file does not pretend otherwise --
 * it pins the four properties that were wrong and that a rewrite could undo
 * without anybody noticing, and it does it by reading COMPUTED STYLE and
 * GEOMETRY rather than class names, so a restyle that keeps the property
 * passes and a regression that keeps the class fails.
 */
test.describe("the page reads as a file manager", () => {
  test.skip(
    MODE !== "embed",
    "these need the seeded mock volume and its mode hook (internal/webui/mockapi_test.go)",
  );

  test.beforeEach(async ({ playwright, session }) => {
    const request = await playwright.request.newContext();
    await resetHooks(request, session);
    await request.dispose();
  });

  test("the status panel and the file panel are two separate surfaces", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);
    const status = page.getByTestId("pelfs-durability-panel");
    const files = page.getByTestId("pelfs-files-panel");
    await expect(status).toBeVisible();
    await expect(files).toBeVisible();

    // Neither contains the other: they are siblings on the workspace, not one
    // strip of prose above a grid.
    expect(
      await status.evaluate((el, other) => el.contains(other), await files.elementHandle()),
    ).toBe(false);

    // Each one is a bordered, filled surface, and there is real space between
    // them. This is the "physical separation" complaint, as numbers.
    for (const panel of [status, files]) {
      const box = await panel.evaluate((el) => {
        const cs = getComputedStyle(el);
        return {
          border: parseFloat(cs.borderTopWidth),
          radius: parseFloat(cs.borderTopLeftRadius),
          background: cs.backgroundColor,
        };
      });
      expect(box.border, "a panel has a border").toBeGreaterThanOrEqual(1);
      expect(box.radius, "a panel has a radius").toBeGreaterThan(0);
      expect(box.background).not.toBe("rgba(0, 0, 0, 0)");
    }

    const a = (await status.boundingBox())!;
    const b = (await files.boundingBox())!;
    expect(b.y - (a.y + a.height), "a gap between the two panels").toBeGreaterThan(2);

    // And the ground they sit on is not the colour they are, or the borders
    // are the only thing saying so.
    const ground = await page
      .locator(".pelfs-workspace")
      .evaluate((el) => getComputedStyle(el).backgroundColor);
    const surface = await status.evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(surface, "the panels are a different surface from the workspace").not.toBe(ground);
  });

  test("the search box looks like a text box, and says so when focused", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);
    await expect(card(page, "/README.txt")).toBeVisible();

    // A real <input>, with a placeholder, inside the file panel -- not a
    // borderless div that happens to accept typing.
    const box = page.getByTestId("pelfs-files-panel").locator("input[type=text]").first();
    await expect(box).toBeVisible();
    await expect(box).toHaveAttribute("placeholder", /search/i);

    const resting = await box.evaluate((el) => {
      const cs = getComputedStyle(el);
      return { border: parseFloat(cs.borderTopWidth), background: cs.backgroundColor };
    });
    expect(resting.border, "the search box has a border").toBeGreaterThanOrEqual(1);
    expect(resting.background, "the search box has a surface of its own").not.toBe(
      "rgba(0, 0, 0, 0)",
    );

    // And focus is VISIBLE. Which property carries it is a design choice, so
    // this asserts that the rendered ring changes, not which rule drew it.
    const ring = (el: HTMLElement) => {
      const cs = getComputedStyle(el);
      return `${cs.outlineStyle}|${cs.outlineWidth}|${cs.borderTopColor}|${cs.boxShadow}`;
    };
    const atRest = await box.evaluate(ring);
    await box.focus();
    const onFocus = await box.evaluate(ring);
    expect(onFocus, "focus must change how the search box is drawn").not.toBe(atRest);
    expect(
      await box.evaluate((el) => parseFloat(getComputedStyle(el).outlineWidth)),
      "a focus ring with a width",
    ).toBeGreaterThan(0);
  });

  test("there is no glyph legend, and the caveats are a disclosure rather than a wall", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);
    await expect(card(page, "/README.txt")).toBeVisible();

    // The legend is GONE, on purpose: each glyph appears beside its own words
    // in the durability sentence, so a legend was a second copy of the text.
    // The contract it stood for -- three states, three different characters --
    // is asserted in durability.spec.ts against what the panel renders.
    await expect(page.getByTestId("durability-legend")).toHaveCount(0);

    // The search caveat is TRUE and it is QUIET: a short summary on the file
    // pane's own bar, with the whole sentence one click away. What it must not
    // be again is a paragraph of implementation detail across the top of the
    // page before anyone has typed anything.
    const caveat = page.getByTestId("search-scope");
    await expect(caveat).toBeVisible();
    await expect(caveat).toHaveAttribute("data-searching", "no");
    const summary = caveat.locator("summary");
    const words = ((await summary.textContent()) ?? "").trim();
    expect(words.length, "the caveat's summary is a phrase, not a paragraph").toBeLessThan(60);
    // Closed, the long form is not on the screen.
    await expect(caveat.locator(".pelfs-caveat__body")).toBeHidden();

    // Opened, the fact is there in full -- including the half a user cannot
    // guess: that the search never reaches the server.
    await summary.click();
    const body = caveat.locator(".pelfs-caveat__body");
    await expect(body).toBeVisible();
    await expect(body).toContainText("asks the server nothing");
    await expect(body).toContainText("pelfs mount");
  });

  test("a read-only session renders no publish control at all", async ({
    page,
    session,
    playwright,
  }) => {
    // THE DEFAULT SESSION. `pelfs browse` is read-only unless --rw, so this is
    // the common case, and it used to render a disabled "Publish now" at the
    // top of the page beside a hint explaining what read-only means -- under a
    // durability line that had already said "read-only". One sentence, no dead
    // control.
    const request = await playwright.request.newContext();
    await testHook(request, session, { mode: "read-only" });

    await openPelfs(page, session);
    const line = page.getByTestId("durability");
    await expect(line).toContainText("read-only");
    await expect(
      page.getByTestId("publish-button"),
      "a session that cannot publish must not render a publish button",
    ).toHaveCount(0);
    // The consequence is still said, once, where the control would have been.
    await expect(page.getByTestId("publish-hint")).toContainText("--rw");
    await request.dispose();
  });

  test("a writable session with something staged puts the publish control in the panel", async ({
    page,
    session,
  }) => {
    // The other half of the pair: when publishing IS possible the control is
    // there, in the status panel, and enabled -- demoted from the top of the
    // page but not hidden from the person who needs it.
    await openPelfs(page, session);
    await page.locator("input[type=file]").first().setInputFiles({
      name: "chrome-check.dat",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("bytes\n"),
    });
    await expect(page.getByTestId("durability")).toHaveAttribute("data-durability", "staged");

    const button = page.getByTestId("publish-button");
    await expect(button).toBeEnabled();
    await expect(button).toHaveAttribute("data-publish-state", "ready");
    // In the status panel, not floating in the header.
    expect(
      await page
        .getByTestId("pelfs-durability-panel")
        .evaluate((el, btn) => el.contains(btn), await button.elementHandle()),
    ).toBe(true);
    // Publish it, so the next spec's "nothing is staged yet" holds.
    await button.click();
    await expect(page.getByTestId("publish-status")).toHaveAttribute("data-job-state", "done");
  });
});
