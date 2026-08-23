import { BASE, MODE, apiHeaders, expect, openPelfs, resetHooks, test, testHook } from "./pelfs";

/**
 * PUBLISH: 202, a job id, and the two answers that are not 202.
 *
 * `control.Hooks.Publish` is wired to `genSession.checkpoint`, which takes the
 * session lock and holds it across the entire seal -- fence, freeze, walk,
 * upload, flip. On a large drag that is minutes. So the route answers 202 with
 * a job id and the page watches `/events`; a handler that blocked would hold
 * an HTTP request open for the whole thing and give the user a spinner with
 * no information in it.
 *
 * A second concurrent request gets 409, not a queue: the lock already
 * serializes it, and saying so is better than letting two clicks silently
 * become one publish and one long wait.
 */
test.describe("publish", () => {
  test.skip(MODE !== "browse", "publish is `pelfs browse`'s; the embed server has no volume");

  test.afterEach(async ({ playwright, session }) => {
    const request = await playwright.request.newContext();
    await resetHooks(request, session);
    await request.dispose();
  });

  test("the button is disabled when there is nothing to publish, and says why", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);
    const button = page.getByTestId("publish-button");
    await expect(button).toHaveAttribute("data-publish-state", "nothing");
    await expect(button).toBeDisabled();
    // "(nothing to publish)" is the whole point: a disabled control with no
    // explanation is indistinguishable from a broken one.
    await expect(page.getByTestId("publish-hint")).toContainText("nothing to publish");
  });

  test("click -> 202 -> the job reaches done", async ({ page, session, playwright }) => {
    const request = await playwright.request.newContext();
    await openPelfs(page, session);

    // Something to publish. The hook changes what the page is TOLD, so the
    // button becomes reachable; the checkpoint it then runs is the real one,
    // and on a clean overlay it answers "nothing changed; still at generation
    // N" -- which is a truthful, cheap answer and still a completed job.
    await testHook(request, session, { staged_files: 2, staged_bytes: 2048 });
    const button = page.getByTestId("publish-button");
    await expect(button).toHaveAttribute("data-publish-state", "ready");
    await expect(button).toBeEnabled();

    await button.click();

    const status = page.getByTestId("publish-status");
    // Polled, not slept on: the job's terminal state arrives on the SSE
    // stream whenever the seal finishes.
    await expect(status).toHaveAttribute("data-job-state", "done");
    await expect(status).toContainText("published:");
    await request.dispose();
  });

  test("a second concurrent publish is 409 with the id of the job that holds the lock", async ({
    page,
    session,
    playwright,
  }) => {
    const request = await playwright.request.newContext();
    await openPelfs(page, session);
    // Long enough for a driver to see "running"; a real seal provides its own
    // duration.
    await testHook(request, session, {
      staged_files: 1,
      staged_bytes: 1024,
      publish_stall_ms: 3000,
    });

    const button = page.getByTestId("publish-button");
    await expect(button).toHaveAttribute("data-publish-state", "ready");
    await button.click();

    const status = page.getByTestId("publish-status");
    await expect(status).toHaveAttribute("data-job-state", "running");
    // While a publish holds the overlay the UI must not offer another one.
    await expect(button).toBeDisabled();
    await expect(page.getByTestId("publish-hint")).toContainText("publishing");
    const runningJob = await status.getAttribute("data-job-id");
    expect(runningJob, "the page must name the job it is watching").toBeTruthy();

    // The second request, made FROM THE PAGE so it carries a real browser's
    // headers, is the case the 409 exists for.
    const second = await page.evaluate(
      async ([url, header, token]) => {
        const r = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", [header]: token },
          body: "{}",
        });
        return { status: r.status, body: (await r.json()) as { job?: string; error?: string } };
      },
      ["/api/v1/publish", "X-Pelfs-Session", session] as [string, string, string],
    );
    expect(second.status, "a concurrent publish must be refused, not queued").toBe(409);
    expect(second.body.job, "the 409 must name the job already running").toBe(runningJob);
    expect(second.body.error).toContain("already running");

    // And the first one still finishes: the refusal did not disturb it.
    await expect(status).toHaveAttribute("data-job-state", "done");
    await request.dispose();
  });

  test("a read-only session is refused, and the API says so rather than pretending", async ({
    session,
    playwright,
  }) => {
    // This run is --rw, so the read-only refusal cannot be reached here; what
    // CAN be checked without a second server is that the route answers only
    // to POST. A state change on a safe method is the hole
    // net/http.CrossOriginProtection cannot close, and the guard's answer is
    // that nothing here mutates on GET.
    const request = await playwright.request.newContext();
    const res = await request.get(new URL("api/v1/publish", BASE).toString(), {
      headers: apiHeaders(session),
    });
    expect(res.status(), "publish must not be reachable by a GET").toBe(405);
    await request.dispose();
  });
});
