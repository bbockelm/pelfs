import { MODE, expect, openPelfs, resetHooks, test, testHook } from "./pelfs";

/**
 * THE BRANCH PILL AS A CONTROL, AND THE ONE THING IT MUST NOT SAY.
 *
 * "I feel like I should be able to click on the 'branch' pill and get a
 * drop-down to show other branches." The control is ui/BranchPicker.tsx and
 * the routes are cmd/pelfs/browsebranch.go's; this file drives both against
 * the mock server, which grew them (internal/webui/mockapi_test.go) so that
 * embed mode stops exercising only the DEGRADED path. Until it had
 * `/api/v1/branches`, `listBranches` reported "unsupported" here and the
 * picker fell back to the static pill — so every property below was reachable
 * in browse mode alone, and browse mode has one branch and no way to make a
 * second from a browser.
 *
 * THE ASSERTION THAT MATTERS MOST IS ABOUT WORDING. A switch is reported in
 * the PUBLISH job slot with `reason: "branch"`, because a switch and a seal
 * both hold the session lock end to end and a second slot would be a second
 * name for the same queue. A page that rendered that as "publishing…" would
 * tell the user their bytes were being written to the federation while the
 * session was reopening an overlay on another head — on the one panel whose
 * entire purpose is to be trusted about exactly that question.
 *
 * AND THE 409, which is what a real session with an afternoon of uploads in
 * it gets: the switch is refused, the server says why, and the page shows the
 * server's reason rather than a shrug.
 */
test.describe("the branch picker", () => {
  test.skip(
    MODE !== "embed",
    "the mock volume is the only one in the suite with more than one branch",
  );

  test.afterEach(async ({ playwright, session }) => {
    const request = await playwright.request.newContext();
    await resetHooks(request, session);
    await request.dispose();
  });

  test("the pill is a drop-down of the volume's branches", async ({ page, session }) => {
    await openPelfs(page, session);

    const pill = page.getByTestId("branch");
    await expect(pill).toHaveAttribute("data-branch-control", "select");
    const select = page.getByTestId("branch-select");
    // The value is the branch the /events snapshot says this session is on,
    // and it must be one of the options or the browser shows the first row —
    // a control that lies about where you are.
    await expect(select).toHaveValue("main");
    await expect(select.locator("option")).toHaveCount(3);
    // The generation rides along, because the list is also the answer to
    // "which of these did I publish from".
    await expect(select.locator("option[value='dev']")).toContainText("gen 91");
  });

  test("a switch says it is a switch, and never says publishing", async ({
    page,
    session,
    playwright,
  }) => {
    const request = await playwright.request.newContext();
    // A switch long enough to assert what the page says WHILE it runs. Not a
    // sleep in the test: the server is told to take its time, and every
    // assertion below still polls.
    await testHook(request, session, { switch_stall_ms: 3000 });
    await openPelfs(page, session);

    const select = page.getByTestId("branch-select");
    await select.selectOption("dev");

    const status = page.getByTestId("publish-status");
    await expect(status).toHaveAttribute("data-job-state", "running");
    await expect(status).toContainText("switching branches");
    // THE WHOLE POINT. Nothing is going to the federation.
    await expect(status).not.toContainText("publishing");
    await expect(page.getByTestId("publish-hint")).toContainText("switching branches");
    // The overlay is held either way, so the control that would write to it
    // is disabled while this runs.
    await expect(page.getByTestId("publish-button")).toBeDisabled();

    // The select shows the SERVER's branch, not the click: a 202 is not a
    // switch, and a control that jumped ahead would be showing a branch this
    // session is not on for as long as the switch took — and forever if it
    // were refused.
    await expect(select).toHaveValue("main");
    await expect(select).toBeDisabled();
    await expect(page.getByTestId("branch-note")).toContainText("switching to dev");

    // And then the snapshot agrees, and the control follows it.
    await expect(status).toHaveAttribute("data-job-state", "done");
    await expect(status).toContainText("switched: on dev at generation 91");
    await expect(select).toHaveValue("dev");
    await expect(select).toBeEnabled();
    await expect(page.getByTestId("generation")).toContainText("91");
    await request.dispose();
  });

  test("a session with staged work is refused, and the server's reason is on the screen", async ({
    page,
    session,
  }) => {
    // The case a picker exists to survive: switching cannot carry an overlay
    // across, and silently discarding one would lose an afternoon of uploads
    // to a single click.
    await openPelfs(page, session);
    await page.locator("input[type=file]").first().setInputFiles({
      name: "unpublished.dat",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("not in the federation yet\n"),
    });
    await expect(page.getByTestId("durability")).toHaveAttribute("data-durability", "staged");

    const select = page.getByTestId("branch-select");
    await select.selectOption("dev");

    // The server's own reason, not a paraphrase: it is the sentence that
    // tells the user what to do (publish it, or throw it away on purpose).
    const note = page.getByTestId("branch-note");
    await expect(note).toContainText("publish or discard first");
    // Nothing moved: the control is back on the branch the session is really
    // on, usable again, and the staged work is still staged.
    await expect(select).toHaveValue("main");
    await expect(select).toBeEnabled();
    await expect(page.getByTestId("durability")).toHaveAttribute("data-durability", "staged");
    await expect(page.getByTestId("durability")).toContainText("on this machine only");
  });
});
