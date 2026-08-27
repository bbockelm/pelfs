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
 *   "the status bar … is strangely capitalized and repeats things elsewhere in
 *    the UI"
 *   "'whole-file upload only: a dropped connection restarts it…' which is the
 *    exact over-explaining crap I asked you to remove"
 *   "SAME PROBLEM WITH SEARCH ('search covers loaded rows'). I ASKED YOU TO DO
 *    THAT LAST ROUND."
 *
 * The last three are DELETIONS, and a deletion needs a test more than an
 * addition does: nothing about a missing sentence fails on its own, so the
 * only thing standing between "gone" and "back next round, smaller" is an
 * assertion that counts it at zero.
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

  test("no legend, no search caveat, no upload caveat -- the chrome states nothing", async ({
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

    // THE SEARCH CAVEAT IS GONE, and this assertion is the whole point of
    // this test now. It was a paragraph above the grid; it was then made a
    // <details> chip with the same paragraph inside it, which is relocation
    // and not deletion, and the owner said so in as many words: "SAME PROBLEM
    // WITH SEARCH ('search covers loaded rows'). I ASKED YOU TO DO THAT LAST
    // ROUND." So: no chip, no summary, no popover body, and -- because a
    // tooltip is the same move a third time -- no title attribute on the
    // search box either.
    await expect(page.getByTestId("search-scope")).toHaveCount(0);
    await expect(page.getByTestId("search-scope-count")).toHaveCount(0);
    await expect(page.locator(".pelfs-caveat")).toHaveCount(0);
    const box = page.getByTestId("pelfs-files-panel").locator("input[type=text]").first();
    await expect(box).not.toHaveAttribute("title", /./);

    // THE UPLOAD CAVEAT IS GONE FROM THE STATUS LINE, for the same reason:
    // "whole-file upload only: a dropped connection restarts it, and there is
    // no progress bar" stood on every screen before anything had gone wrong.
    // What is left in that bar is the stream light and the third-party notices
    // link, which is a licence obligation rather than a statement.
    const statusline = page.locator(".pelfs-statusline");
    await expect(statusline).not.toContainText("whole-file");
    await expect(statusline).not.toContainText("progress bar");
    await expect(statusline).not.toContainText("dropped connection");
    await expect(page.getByTestId("pelfs-notices-link")).toBeVisible();

    // THE HINT BESIDE THE PUBLISH BUTTON IS GONE. A disabled control reading
    // "Publish now" with "(nothing to publish)" printed next to it is one fact
    // rendered twice, which is what the owner called duplicate info; the
    // button wears the state instead. (The read-only session is the one that
    // still renders a hint, and it renders no button -- see below.)
    const button = page.getByTestId("publish-button");
    await expect(button).toHaveText("Nothing to publish");
    await expect(page.getByTestId("publish-hint")).toHaveCount(0);
    // AND THE IDLE-SEAL CLAUSE IS GONE FROM THE DURABILITY LINE. ", or 30s
    // after this tab closes" was true and was not worth the width; the seal
    // still happens.
    await expect(page.getByTestId("durability")).not.toContainText("after this tab closes");
  });

  test("the durability line answers one question and repeats nothing", async ({
    page,
    session,
    playwright,
  }) => {
    // "The status bar ('✓read-only. everything here is in the federation
    // (generation 5).') is strangely capitalized and repeats things elsewhere
    // in the UI." Both halves, as assertions: it starts with a capital, and
    // the two facts the app bar owns -- the mode chip and the generation --
    // are not said a second time here.
    const request = await playwright.request.newContext();
    await testHook(request, session, { mode: "read-only" });
    await openPelfs(page, session);

    const line = page.getByTestId("durability");
    await expect(line).toHaveAttribute("data-durability", "published");
    // The app bar still owns both facts, which is why the line does not.
    await expect(page.getByTestId("mode")).toHaveText("read-only");
    await expect(page.getByTestId("generation")).toContainText("generation");

    const words = ((await line.textContent()) ?? "").replace(/^[^A-Za-z]*/, "");
    expect(words[0], "the sentence starts with a capital letter").toBe(words[0].toUpperCase());
    expect(words.toLowerCase(), "the line must not repeat the mode chip").not.toContain(
      "read-only",
    );
    expect(words.toLowerCase(), "the line must not repeat the generation").not.toContain(
      "generation",
    );
    // It still answers the only question it is for.
    await expect(line).toContainText("in the federation");
    await request.dispose();
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
    // The mode is the app bar's chip, not the durability line's -- see "the
    // durability line answers one question and repeats nothing" above.
    await expect(page.getByTestId("mode")).toHaveText("read-only");
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
    // The middle of the three states, and the only one that is a live control.
    await expect(button).toHaveText("Publish now");
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

  test("the status line is at the bottom of the viewport", async ({ page, session }) => {
    // "The footer is not at the bottom of the browser on /connect" -- the same
    // property, asserted on this surface too, because the two pages are one
    // product and a footer that floats on either reads as a broken page. The
    // assertion is GEOMETRY rather than a class or a `position` value: whether
    // it is flex, grid or sticky is a design choice, and where it ends up is
    // not.
    await openPelfs(page, session);
    await expect(card(page, "/README.txt")).toBeVisible();
    const bar = page.locator(".pelfs-statusline");
    const box = (await bar.boundingBox())!;
    const viewport = page.viewportSize()!;
    expect(
      viewport.height - (box.y + box.height),
      "the status line's bottom edge is the viewport's",
    ).toBeLessThan(2);
  });
});

/**
 * THE BRANCH PILL IS A CONTROL, IN BOTH MODES, and that is new here.
 *
 * `GET /api/v1/branches` answers in both now -- cmd/pelfs/browsebranch.go for
 * `pelfs browse`, and internal/webui/mockapi_test.go for the embed server,
 * which had no such route and so exercised only the picker's degraded form.
 * So this asserts the settled shape: a real select, whose selected option is
 * the branch the durability stream says this session is on. What it must
 * never be is a control showing a branch the session is not on -- the failure
 * mode of treating a 202 as a switch.
 *
 * What the picker does across a switch, and what it does when one is refused,
 * is branch.spec.ts; this is the invariant that holds in every session.
 */
test.describe("the branch pill", () => {
  test("names the session's branch, and is a real control when the server has one", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);
    const pill = page.getByTestId("branch");
    await expect(pill).toBeVisible();

    // THE PILL STARTS STATIC IN EVERY SESSION, and that is not the degraded
    // form: the picker asks for the list only once the volume is open, so a
    // browse-mode session renders the plain fact for as long as the open
    // takes. Reading `data-branch-control` once, without waiting, is how this
    // spec read "static" off a page that was two frames from being a
    // dropdown. Both servers in this suite answer GET /api/v1/branches, so
    // the settled form is the control, and this waits for it.
    await expect(pill).toHaveAttribute("data-branch-control", "select");

    const select = page.getByTestId("branch-select");
    await expect(select).toBeVisible();
    await expect(select).toBeEnabled();
    // The selected option is the session's branch, and there is exactly one
    // option bearing that name.
    const current = await select.inputValue();
    expect(current, "the picker must have a branch selected").not.toBe("");
    expect(
      await select.locator("option").evaluateAll(
        (opts, want) => opts.filter((o) => (o as HTMLOptionElement).value === want).length,
        current,
      ),
      "the current branch appears once in the list",
    ).toBe(1);
  });
});
