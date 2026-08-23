import { MODE, expect, openPelfs, resetHooks, test, testHook } from "./pelfs";

/**
 * THE DURABILITY CONTRACT, which is the one thing on this page that can hurt
 * somebody.
 *
 * docs/design-webui.md states the failure mode this panel exists to prevent:
 * "a green check for the first row. A file that looks uploaded and is not in
 * the federation is the worst possible ambiguity for this audience, because
 * the user's next action is to close the laptop and tell a collaborator the
 * data is there."
 *
 * So the assertions here are not "the panel renders". They are:
 *   - staged and published are DIFFERENT CHARACTERS, not two colours of one;
 *   - the legend is on the screen, always, not in a tooltip;
 *   - `data-durability` moves to "staged" when something is staged and back
 *     to "published" when it is not, and the words move with it.
 *
 * A fresh volume cannot be staged by itself, and a lease cannot be made stale
 * from outside, so the states come from `--test-hooks`. It sets no state on the
 * volume -- it only changes what the page is TOLD -- which is exactly what a
 * driver test needs and the least dangerous thing that works.
 *
 * WHICH PANEL THIS DRIVES CHANGED IN THE WIRING PASS and the assertions did
 * not, which is the point of them. Before, `/` was M1's hand-written page and
 * these selectors were its ids; now `/` is the React app and they are the
 * app's. The suite did not need editing here because the two surfaces were
 * built to one vocabulary (webui/frontend/src/durability.ts,
 * cmd/pelfs/browse.html, and internal/webui/durability_test.go which fails if
 * they drift) -- so this file is also the standing proof that the vocabulary
 * really is one. The connection page's copy of the panel is driven at
 * /connect by connect.spec.ts.
 */
test.describe("durability", () => {
  test.skip(
    MODE !== "browse",
    "these states come from --test-hooks against a real volume; the embed server has neither",
  );

  test.afterEach(async ({ playwright, session }) => {
    const request = await playwright.request.newContext();
    await resetHooks(request, session);
    await request.dispose();
  });

  test("staged and published are different characters, and the legend is always visible", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);

    const legend = page.getByTestId("durability-legend");
    await expect(legend).toBeVisible();

    const staged = (await page.getByTestId("glyph-staged").textContent())?.trim() ?? "";
    const sending = (await page.getByTestId("glyph-sending").textContent())?.trim() ?? "";
    const published = (await page.getByTestId("glyph-published").textContent())?.trim() ?? "";

    expect(staged, "the staged glyph must exist").not.toBe("");
    expect(published, "the published glyph must exist").not.toBe("");
    // The assertion the whole panel is for. Two shades of one glyph would
    // pass a colour check and fail every colour-blind user, so the SHAPE has
    // to differ.
    expect(
      published,
      "'on this machine only' and 'in the federation' must not be the same character",
    ).not.toBe(staged);
    expect(sending).not.toBe(staged);
    expect(sending).not.toBe(published);

    // And the legend has to say what each one means, in words.
    await expect(legend).toContainText("on this machine only");
    await expect(legend).toContainText("in the federation");
  });

  test("data-durability follows the volume: published -> staged -> published", async ({
    page,
    session,
    playwright,
  }) => {
    const request = await playwright.request.newContext();
    await openPelfs(page, session);

    const line = page.getByTestId("durability");
    // A freshly created volume has nothing staged, so the honest answer is
    // "everything here is in the federation".
    await expect(line).toHaveAttribute("data-durability", "published");
    await expect(line).toContainText("in the federation");

    await testHook(request, session, { staged_files: 3, staged_bytes: 4096 });
    await expect(line).toHaveAttribute("data-durability", "staged");
    await expect(line).toContainText("3 files");
    await expect(line).toContainText("on this machine only");
    // The count of what is NOT published must not be reported as published.
    await expect(line).not.toContainText("everything here is in the federation");

    await testHook(request, session, { reset: true });
    await expect(line).toHaveAttribute("data-durability", "published");
    await request.dispose();
  });

  test("an upload backlog says 'sending', which is neither of the other two", async ({
    page,
    session,
    playwright,
  }) => {
    const request = await playwright.request.newContext();
    await openPelfs(page, session);
    await testHook(request, session, {
      staged_files: 1,
      staged_bytes: 1 << 20,
      upload_backlog: 2 << 20,
    });

    const line = page.getByTestId("durability");
    // Still staged -- packs in flight are not packs landed -- and the arc
    // says the difference.
    await expect(line).toHaveAttribute("data-durability", "staged");
    await expect(line).toContainText("sending");
    await request.dispose();
  });

  test("every lease state that means 'this session cannot publish' is a banner", async ({
    page,
    session,
    playwright,
  }) => {
    const request = await playwright.request.newContext();
    await openPelfs(page, session);

    const lease = page.getByTestId("lease");
    const banner = page.getByTestId("lease-banner");

    // The session really holds a lease: --rw took one before the branch head
    // was read.
    await expect(lease).toHaveAttribute("data-lease-state", "held");
    await expect(banner).toBeHidden();

    // The other three are the control socket's own vocabulary, and each one
    // means something different about what happens at the seal.
    for (const [state, words] of [
      ["stale", "past its TTL"],
      ["interrupted", "vanished"],
      ["lost", "Another client has taken this branch"],
    ] as const) {
      await testHook(request, session, { lease: state });
      await expect(lease).toHaveAttribute("data-lease-state", state);
      await expect(banner).toBeVisible();
      await expect(banner).toContainText(words);
    }

    await testHook(request, session, { reset: true });
    await expect(banner).toBeHidden();
    await request.dispose();
  });

  test("a session running with --test-hooks says so on the page", async ({ page, session }) => {
    // An affordance that lets the UI show states the volume is not in must
    // never be mistaken for the real thing. The suite drives it, so the suite
    // is also what proves the warning is there.
    await openPelfs(page, session);
    await expect(page.getByTestId("test-hooks-banner")).toBeVisible();
    await expect(page.getByTestId("test-hooks-banner")).toContainText("--test-hooks is on");
  });
});
