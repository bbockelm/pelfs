import { BASE, MODE, apiHeaders, expect, openPelfs, resetHooks, test, testHook } from "./pelfs";

/**
 * SSE RECONNECTION, and the property that makes it safe.
 *
 * `/events` carries COMPLETE SNAPSHOTS, not deltas (cmd/pelfs/browse.go,
 * serveEvents). A browser drops and re-establishes this stream on its own -- a
 * suspended laptop, a network blip, a sleeping CI runner -- and if the stream
 * carried deltas, every drop would leave the page showing a state the volume
 * left minutes ago. With snapshots there is nothing to replay and no
 * Last-Event-ID to get wrong.
 *
 * The test is therefore not "it reconnects". It is: END THE STREAM, CHANGE
 * THE STATE WHILE IT IS DOWN, AND WATCH THE PAGE COME BACK CORRECT -- with no
 * reload, because a page that only recovers on F5 has not recovered.
 *
 * HOW THE STREAM IS ENDED, and why not the obvious way. Chromium's offline
 * emulation (`Network.emulateNetworkConditions`, which is also what
 * `context.setOffline` uses) fails NEW requests but does not tear down an
 * open streaming response: measured, the page stayed `data-stream="open"` for
 * the full timeout with the browser "offline". So the stream is intercepted
 * instead and answered with ONE frame that then ends -- and the frame is not
 * fabricated: it is the server's own state document, fetched from
 * `GET /api/v1/info`, which returns exactly what a stream frame carries. From
 * the page's side that is an ordinary short-lived stream, which is precisely
 * the event being tested.
 */
test.describe("the durability stream", () => {
  test.skip(MODE !== "browse", "`/events` is `pelfs browse`'s stream");

  test.afterEach(async ({ playwright, session }) => {
    const request = await playwright.request.newContext();
    await resetHooks(request, session);
    await request.dispose();
  });

  test("a reconnect does not leave a stale view", async ({ page, session, playwright }) => {
    const request = await playwright.request.newContext();

    // One frame, the server's own, and then the connection ends.
    const snapshot = await request.get(new URL("api/v1/info", BASE).toString(), {
      headers: apiHeaders(session),
    });
    expect(snapshot.ok()).toBeTruthy();
    const frame =
      `retry: 500\n\n` + `event: state\ndata: ${JSON.stringify(await snapshot.json())}\n\n`;

    let intercepting = true;
    await page.route("**/events*", async (route) => {
      if (!intercepting) {
        await route.continue();
        return;
      }
      await route.fulfill({
        status: 200,
        headers: { "content-type": "text/event-stream", "cache-control": "no-store" },
        body: frame,
      });
    });

    await openPelfs(page, session);

    const status = page.getByTestId("stream-status");
    const line = page.getByTestId("durability");
    // The frame arrived, so the page rendered it: nothing is staged yet.
    await expect(line).toHaveAttribute("data-durability", "published");
    // ...and then the stream ended, which the page must SAY rather than keep
    // showing a live number as though nothing had happened.
    await expect(status).not.toHaveAttribute("data-stream", "open");

    // The volume changes while the browser cannot see it. This request comes
    // from Node, and the page has no way to learn about it until the stream
    // is back.
    await testHook(request, session, { staged_files: 7, staged_bytes: 7 << 20 });
    // Still the old view, correctly, and correctly labelled as disconnected.
    await expect(line).toHaveAttribute("data-durability", "published");

    // Let the retry through. The browser reopens the stream on its own; the
    // first frame on the new connection is a COMPLETE snapshot, so the page
    // is right again with no reload and no replay.
    intercepting = false;
    await expect(status).toHaveAttribute("data-stream", "open");
    await expect(line).toHaveAttribute("data-durability", "staged");
    await expect(line).toContainText("7 files");
    await request.dispose();
  });

  test("the stream refuses a request with no session token", async ({ playwright }) => {
    // EventSource cannot set a header, so the token is in the query string --
    // acceptable there and only there. It is still required.
    const request = await playwright.request.newContext();
    const res = await request.get(new URL("events", BASE).toString(), {
      headers: { Origin: new URL(BASE).origin, "Sec-Fetch-Site": "same-origin" },
    });
    expect(res.status()).toBe(401);
    await request.dispose();
  });
});
