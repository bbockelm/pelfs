import { MODE, expect, openPelfs, resetHooks, test, testHook } from "./pelfs";

/**
 * THE VOLUME THAT WOULD NOT OPEN, WHICH IS THE ONE THE OWNER ACTUALLY HIT.
 *
 * The report: "whenever I start read-write, I just get a page that says
 * 'reading the overlay…'. Never seems to progress." The cause was a branch
 * lease that a `--rw` session which did not exit cleanly leaves behind for a
 * TTL, so the next `--rw` start is refused — and the refusal used to race the
 * browser: the URL was printed before the volume was opened, and the process
 * exited during the second the tab took to attach.
 *
 * The server half is fixed (cmd/pelfs/browsefail.go): the listener stays up,
 * and `state.error` carries a whole sentence — what refused, where this
 * session's state directory is, and what to do next. THIS FILE IS THE OTHER
 * HALF. Both surfaces used to render every phase that was not "ready" as
 * "Reading the overlay…", so a served reason and a raced one looked identical
 * on screen and the reported symptom was unchanged.
 *
 * WHY THIS IS EMBED-ONLY. A real failed open ends the process it happened in,
 * and `pelfs browse` has no hook that fakes one — nor should it, since the
 * whole fix is about a session that is genuinely refusing. The mock server
 * (internal/webui/mockapi_test.go) can report the phase, which is what makes
 * the PAGE's behaviour assertable at all.
 */

// The real sentence, in the real shape: an error, then the state directory,
// then what to do next. It is not paraphrased here because the assertions
// below are that the page does not paraphrase it either.
const LEASE_REFUSAL =
  "branch main: held by pelfs@ap40.example (expires in 1m47s)\n" +
  "this session's state is /home/researcher/.local/state/pelfs/vol-3f1a9c04.\n" +
  "if that holder is a pelfs you killed, it is gone but its lease is not: wait for the " +
  "expiry above and start again, or start read-only now (`pelfs browse --ro`) to read what " +
  "is published while you wait.";

test.describe("a failed open", () => {
  test.skip(
    MODE !== "embed",
    "a real failed open ends the process; only the mock server can report the phase",
  );

  test.afterEach(async ({ playwright, session }) => {
    const request = await playwright.request.newContext();
    await resetHooks(request, session);
    await request.dispose();
  });

  test("says why, in the server's own words, instead of 'reading the overlay…'", async ({
    page,
    session,
    playwright,
  }) => {
    const request = await playwright.request.newContext();
    // Set BEFORE the page loads: this is a volume that never opened, not one
    // that stopped working, and the difference is what the app boots into.
    await testHook(request, session, { phase: "failed", error: LEASE_REFUSAL });
    await openPelfs(page, session);

    const line = page.getByTestId("durability");
    await expect(line).toHaveAttribute("data-durability", "failed");
    // The panel's own edge carries it too, so the state is visible without
    // reading a word.
    await expect(page.getByTestId("pelfs-durability-panel")).toHaveAttribute(
      "data-durability",
      "failed",
    );

    // THE WHOLE SENTENCE, NOT A SUMMARY OF IT. Each of the three facts is
    // asserted separately, because each one is a different thing the reader
    // does next: what refused, where the state is, and how to get moving
    // again without waiting.
    await expect(line).toContainText("held by pelfs@ap40.example");
    await expect(line).toContainText("/home/researcher/.local/state/pelfs/vol-3f1a9c04");
    await expect(line).toContainText("pelfs browse --ro");

    // And not a word of progress anywhere on the page: this is the symptom
    // that was reported, and nothing about the server fix removed it.
    await expect(line).not.toContainText("Reading the overlay");
    await expect(page.getByTestId("phase-banner")).toHaveCount(0);
    // The state that used to be borrowed for this: "The volume is open but
    // the JSON data plane did not answer" is false when the volume never
    // opened, and it was the app's rendering of exactly this frame.
    await expect(page.locator("body")).not.toContainText("The volume is open");
    await request.dispose();
  });

  test("renders a stopped state, not a loading one", async ({ page, session, playwright }) => {
    const request = await playwright.request.newContext();
    await testHook(request, session, { phase: "failed", error: LEASE_REFUSAL });
    await openPelfs(page, session);

    // A FOURTH CHARACTER. The three durability glyphs are three different
    // shapes because colour alone fails roughly one man in twelve; a failed
    // open is a fourth state and gets the same treatment.
    const glyph = ((await page.getByTestId("durability-glyph").textContent()) ?? "").trim();
    expect(glyph, "a failed open needs a glyph of its own").not.toBe("");
    expect(glyph).not.toBe("✓");
    expect(glyph).not.toBe("●");
    expect(glyph).not.toBe("◔");

    // NO CONTROL AND NO HINT. There is no volume, so a publish button is a
    // lever attached to nothing and "(waiting for the volume)" is a promise
    // nobody is keeping.
    await expect(page.getByTestId("publish-button")).toHaveCount(0);
    await expect(page.getByTestId("publish-hint")).toHaveCount(0);
    // No file grid either: a listing would be 503s against a volume that is
    // not coming.
    await expect(page.getByTestId("pelfs-files-panel")).toHaveCount(0);
    await request.dispose();
  });
});
