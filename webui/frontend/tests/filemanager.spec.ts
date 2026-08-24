import { MODE, card, expect, openPelfs, resetHooks, test } from "./pelfs";

/**
 * THE FILE MANAGER ITSELF, driven against the mock JSON API
 * (internal/webui/mockapi_test.go).
 *
 * Work item U11 owns the real `/api/v1`; it is a sibling's and it has not
 * landed. Rather than ship an app nobody has run, the embedded-bundle server
 * answers the eleven-route contract the U0 recording pins, with the two rules
 * that make these assertions mean something: the session header is required
 * on every request, and a mutation must be `application/json`. Both are
 * exactly what internal/httpguard enforces, so a regression in the provider's
 * `send()` override -- the three-line fix for a component that drops
 * `setHeaders()` and posts `text/plain` -- fails here as a file manager that
 * cannot list a directory, which is how it would fail for a user.
 *
 * WHAT EACH TEST IS FOR is stated on the test, because "the grid renders" is
 * not worth a browser and none of these are that.
 */
test.describe("the file manager", () => {
  // EMBED MODE, and no longer because the app is unreachable elsewhere --
  // `pelfs browse` serves this same bundle at `/` since the wiring pass. It is
  // because these assertions need a volume whose CONTENTS the test chose: a
  // named file to list, a 6,000-entry directory for the cap, a path that
  // refuses a rename. A fresh real volume has none of those, and creating them
  // through the UI would be testing the upload path instead of the thing under
  // test. The file manager against a REAL volume is the last describe block in
  // this file, and it runs in browse mode.
  test.skip(
    MODE !== "embed",
    "these assertions need the seeded mock volume (internal/webui/mockapi_test.go)",
  );

  // One volume serves the whole run, so a test that uploads a file would
  // leave the next test's "nothing is staged yet" precondition false. Order
  // dependence is the same class of flakiness as a fixed sleep, so the mock
  // is put back before each test rather than the tests being written to
  // tolerate each other.
  test.beforeEach(async ({ playwright, session }) => {
    const request = await playwright.request.newContext();
    await resetHooks(request, session);
    await request.dispose();
  });

  test("the session credential reaches the wire, so a listing arrives at all", async ({
    page,
    session,
  }) => {
    // The U0 probe measured that `provider.setHeaders()` never reaches the
    // wire -- RestDataProvider.send() ignores this._customHeaders -- and the
    // session token IS the credential. Without the override the mock answers
    // 401 to the first listing and this page shows its "no data plane"
    // banner instead of a tree.
    await openPelfs(page, session);
    await expect(page.getByTestId("pelfs-shell")).toBeVisible();
    await expect(card(page, "/data")).toBeVisible();
    await expect(card(page, "/README.txt")).toBeVisible();
    // The durability panel is above the files, not behind a tab, and it is its
    // own panel rather than a strip of prose (tests/chrome.spec.ts holds that
    // line in detail).
    await expect(page.getByTestId("durability")).toBeVisible();
    await expect(page.getByTestId("pelfs-durability-panel")).toBeVisible();
  });

  test("one listing per directory, and exactly one -- the store asks twice", async ({
    page,
    session,
  }) => {
    // The probe caught the store emitting `request-data` TWICE for one
    // navigation, and the shipped provider registers no handler for it at
    // all. wireLazyLoading supplies the handler and the in-flight guard; on a
    // capped 5,000-entry directory the guard is the difference between one
    // listing and two.
    const listings: string[] = [];
    page.on("request", (r) => {
      const u = new URL(r.url());
      if (u.pathname.startsWith("/api/v1/files")) listings.push(u.pathname);
    });

    await openPelfs(page, session);
    await expect(card(page, "/data")).toBeVisible();
    await card(page, "/data").dblclick();
    await expect(card(page, "/data/sample.root")).toBeVisible();

    await expect(async () => {
      const forData = listings.filter((p) => p.includes("%2Fdata"));
      expect(forData, `listings for /data: ${forData.join(", ")}`).toHaveLength(1);
    }).toPass({ timeout: 2000 });
  });

  test("a capped directory says so, with the TRUE count", async ({ page, session }) => {
    // The component does not virtualize (measured: 100,000 entries -> 703 MB
    // of heap), so the API caps. A cap the UI does not admit to is a UI that
    // says a directory has 5,000 entries when it has six thousand -- or two
    // million.
    await openPelfs(page, session);
    await card(page, "/large").dblclick();

    const cap = page.getByTestId("listing-cap");
    await expect(cap).toBeVisible();
    await expect(cap).toHaveAttribute("data-listing-total", "6000");
    await expect(cap).toHaveAttribute("data-listing-returned", "5000");
    // The two numbers, which is the whole of what a user needs to know that
    // the folder is bigger than the screen.
    await expect(cap).toContainText("5,000");
    await expect(cap).toContainText("6,000");
    // AND NOTHING ELSE. The disclosure that used to open to a paragraph about
    // virtualization and heap size is deleted: a count is a fact, and the
    // explanation of why the cap exists is not something a person standing in
    // a folder needs. It is not a <details> any more, so there is nothing to
    // open and no hidden body to assert.
    await expect(cap.locator("summary")).toHaveCount(0);
  });

  /*
   * DELETED: "the partial search is admitted, beside the search box, and says
   * how much". It drove the <details> chip and the "searching N loaded rows"
   * summary, and both are gone from the UI on the owner's instruction, given
   * twice -- so the spec goes with them rather than being weakened into
   * asserting a smaller version of something he asked to have removed. The
   * fact it was defending is KL-19 in docs/known-issues.md; that the chip
   * STAYS gone is asserted in tests/chrome.spec.ts, which is the file that
   * owns "what is on the screen".
   */
  test("create a folder: the mutation is application/json, or the guard 415s it", async ({
    page,
    session,
  }) => {
    // Finding 2 of the U0 probe: every mutation goes out as
    // `text/plain;charset=UTF-8`, which internal/httpguard answers with 415.
    // The mock applies the same rule, so this test fails as an error banner
    // and a missing folder if the override regresses.
    const types: string[] = [];
    page.on("request", (r) => {
      if (r.method() === "POST" && new URL(r.url()).pathname.startsWith("/api/v1/files")) {
        types.push(r.headers()["content-type"] ?? "");
      }
    });

    await openPelfs(page, session);
    await page.getByText("Add New", { exact: true }).click();
    await page.getByText("Add new folder", { exact: true }).click();
    const input = page.locator(".wx-modal input");
    await input.fill("browser-made");
    await input.press("Enter");

    await expect(card(page, "/browser-made")).toBeVisible();
    await expect(page.getByTestId("pelfs-error")).toBeHidden();
    expect(types).toContain("application/json");
  });

  test("an upload says what 'uploaded' means, and the panel agrees", async ({ page, session }) => {
    // The moment the design exists to protect: the file appears in the grid,
    // the bytes are in the local overlay, and the user's next action is to
    // close the laptop and tell a collaborator the data is there.
    await openPelfs(page, session);
    await expect(page.getByTestId("durability")).toHaveAttribute("data-durability", "published");

    await page.locator('input[type=file]').first().setInputFiles({
      name: "measurement.dat",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("some measured bytes\n"),
    });

    await expect(card(page, "/measurement.dat")).toBeVisible();
    const notice = page.getByTestId("upload-notice");
    await expect(notice).toBeVisible();
    // ONE SENTENCE, AND IT IS THE OWNER'S. Ours was four -- the overlay,
    // durability against a crash, invisibility to the federation, and what the
    // line above meant -- and the verdict was "WAAY to wordy". Asserted whole,
    // because a budget would let it grow back up to the budget.
    await expect(notice).toHaveText(
      'File uploaded to local machine; click "Publish now" to push it to the federation',
    );
    // And the durability line, which is the authority, agrees with it.
    await expect(page.getByTestId("durability")).toHaveAttribute("data-durability", "staged");
    await expect(page.getByTestId("durability")).toContainText("on this machine only");
  });

  test("publish from the file manager: 202, then the panel says published", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);
    // Stage something so there is anything to publish.
    await page.locator('input[type=file]').first().setInputFiles({
      name: "to-publish.dat",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("bytes\n"),
    });
    const line = page.getByTestId("durability");
    await expect(line).toHaveAttribute("data-durability", "staged");

    const button = page.getByTestId("publish-button");
    await expect(button).toHaveAttribute("data-publish-state", "ready");
    await button.click();

    await expect(page.getByTestId("publish-status")).toHaveAttribute("data-job-state", "done");
    await expect(line).toHaveAttribute("data-durability", "published");
    await expect(line).toContainText("in the federation");
  });

  test("a rename stages no bytes and is still unpublished work", async ({ page, session }) => {
    // THE GESTURE ITSELF, not a hook that describes it. The mock's rename
    // leaves exactly what overlay.Rename leaves -- a whiteout for the old name
    // and an edge for the new one, no staged file and no staged byte
    // (internal/webui/mockapi_test.go, stageEdges) -- which is why the panel
    // used to say "Everything here is in the federation." over a button
    // reading "Nothing to publish" the moment a user renamed something.
    //
    // The sentence is the other half: it is byte-shaped, and a panel that
    // merely started rendering it here would report the size of the change as
    // zero while claiming there is one.
    await openPelfs(page, session);
    const line = page.getByTestId("durability");
    await expect(line).toHaveAttribute("data-durability", "published");

    const before = card(page, "/README.txt");
    await expect(before).toBeVisible();
    await before.click({ button: "right" });
    await page.getByText("Rename", { exact: true }).first().click();
    const input = page.locator(".wx-modal input, .wx-item input").first();
    await input.fill("MEASUREMENTS.txt");
    await input.press("Enter");
    await expect(card(page, "/MEASUREMENTS.txt")).toBeVisible();

    await expect(line).toHaveAttribute("data-durability", "staged");
    await expect(line).toContainText("Changes on this machine only.");
    await expect(line).not.toContainText("0 files");
    await expect(line).not.toContainText("0 B");

    const button = page.getByTestId("publish-button");
    await expect(button).toHaveAttribute("data-publish-state", "ready");
    await expect(button).toHaveText("Publish now");
    await expect(button).toBeEnabled();
  });

  test("A REFUSED RENAME DOES NOT STAY ON THE SCREEN", async ({ page, session }) => {
    // THE TEST THAT PINS KI-11, and the reason it is worth a browser.
    //
    // The store applies every mutation OPTIMISTICALLY: it renames the node and
    // re-parents its children before the provider is reached at all. Upstream's
    // `RestDataProvider.send` then attaches its `.catch` after its own
    // `!res.ok` throw, so a refusal resolved to `undefined` and the promise
    // never rejected -- and the row kept the new name. `PelfsDataProvider.send`
    // fixed the swallowing; that alone left a banner saying "that did not
    // happen" beside a row showing that it had, and of the two a user believes
    // the row.
    //
    // So there are TWO assertions here and neither is sufficient alone:
    //
    //   1. the user is TOLD, in words, with the server's own reason in them;
    //   2. the row is BACK, under its original name, and the name the user
    //      typed is nowhere on the screen.
    //
    // Neither a Go test nor the contract replay can make the second one: the
    // server's 403 is correct in both, and what the component then does with it
    // is only observable in a browser.
    //
    // The refusal is a real HTTP 403 from the mock (mockEntry.ro), not an
    // intercepted route -- so this drives the whole chain: the guard-shaped
    // status, the provider's `explain`, the re-listing, and the store.
    await openPelfs(page, session);
    const before = card(page, "/read-only.dat");
    await expect(before).toBeVisible();

    // The mint of the rename, and the re-read that repairs it, are both
    // watched: the repair is the mechanism, so a test that passed because the
    // component happened not to apply the change would be worth nothing.
    const calls: string[] = [];
    page.on("request", (r) => {
      const u = new URL(r.url());
      if (u.pathname.startsWith("/api/v1/files")) calls.push(`${r.method()} ${u.pathname}`);
    });

    await before.click({ button: "right" });
    await page.getByText("Rename", { exact: true }).first().click();
    const input = page.locator(".wx-modal input, .wx-item input").first();
    await input.fill("renamed-by-the-browser.dat");
    await input.press("Enter");

    // (1) the user is told, and the server's own sentence is in it.
    const banner = page.getByTestId("pelfs-error");
    await expect(banner).toBeVisible();
    await expect(banner).toContainText("403");
    await expect(banner).toContainText("permission denied");

    // (2) the row is the volume's row again. This is the assertion KI-11 was
    // filed for: before the fix this locator was absent and the renamed one
    // was present, with the banner underneath saying otherwise.
    await expect(before, "the refused rename must not survive on the screen").toBeVisible();
    await expect(card(page, "/renamed-by-the-browser.dat")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText("renamed-by-the-browser.dat");

    // And the repair really was a re-read of the directory, not a guess about
    // what the store had done.
    expect(calls, `requests to /api/v1/files: ${calls.join(", ")}`).toContain(
      "PUT /api/v1/files/%2Fread-only.dat",
    );
    await expect(async () => {
      expect(
        calls.filter((c) => c === "GET /api/v1/files"),
        `root listings: ${calls.join(", ")}`,
      ).not.toHaveLength(0);
    }).toPass({ timeout: 2000 });
  });

  test("a refused delete leaves the file where it was", async ({ page, session }) => {
    // The same mechanism through a different action, because `getHandlers`
    // wraps all five and a fix that only covered rename would pass the test
    // above and leave the worst case -- a delete -- looking successful.
    await openPelfs(page, session);
    const file = card(page, "/read-only.dat");
    await expect(file).toBeVisible();

    await file.click({ button: "right" });
    await page.getByText("Delete", { exact: true }).first().click();
    // The component confirms a delete; the button is in its own modal.
    const confirm = page.locator(".wx-modal button", { hasText: /delete|ok|yes/i }).first();
    if (await confirm.count()) await confirm.click();

    await expect(page.getByTestId("pelfs-error")).toContainText("permission denied");
    await expect(file, "a refused delete must not remove the row").toBeVisible();
  });

  test("download goes through a ticket, and the page stays where it is", async ({
    page,
    session,
  }) => {
    await openPelfs(page, session);
    const file = card(page, "/README.txt");
    await expect(file).toBeVisible();

    const mints: string[] = [];
    page.on("request", (r) => {
      const u = new URL(r.url());
      if (u.pathname === "/api/v1/download" || u.pathname.startsWith("/d/")) mints.push(u.pathname);
    });

    const download = page.waitForEvent("download");
    await file.click({ button: "right" });
    await page.getByText("Download", { exact: true }).first().click();
    await download;

    // The authenticated mint, then the credential-free redemption. An <a
    // href> cannot carry a header, so this two-step is the only shape that
    // does not put an ambient credential on a GET.
    expect(mints.some((p) => p === "/api/v1/download")).toBeTruthy();
    expect(mints.some((p) => p.startsWith("/d/"))).toBeTruthy();
    await expect(page.getByTestId("pelfs-shell")).toBeVisible();
  });
});

/**
 * THE FILE MANAGER AGAINST A REAL VOLUME, which is the assertion the wiring
 * pass exists to make possible and the one nothing above can make.
 *
 * Everything in the describe block above runs against a mock: a real
 * implementation of the eleven-route contract, but in memory, with no overlay,
 * no packs, no federation and no seal. This one drag-and-drop goes through
 * `pelfs browse --rw` into a real write overlay on a real v2 volume, and then
 * publishes it to a fakeorigin federation -- so it is the whole trap this
 * design was built to close, closed, in one test:
 *
 *   upload -> the grid shows the file, and the panel says ON THIS MACHINE ONLY
 *          -> Publish now
 *          -> the panel says IN THE FEDERATION, with a generation.
 *
 * IT PUBLISHES ON PURPOSE, and not only for the last assertion: the volume is
 * shared by every spec in this run (one server, `fullyParallel: false`), and a
 * test that left a file staged would make the next file's "nothing is staged
 * yet" precondition false. Ending clean is the same discipline as the mock's
 * reset hook, done the only way a real volume allows.
 */
test.describe("the file manager on a real volume", () => {
  test.skip(MODE !== "browse", "needs `pelfs browse --rw` and a real overlay");

  test("upload, staged, publish, in the federation", async ({ page, session }) => {
    await openPelfs(page, session);
    const line = page.getByTestId("durability");
    // A fresh volume: nothing staged, and the panel says so rather than
    // saying nothing.
    await expect(line).toHaveAttribute("data-durability", "published");

    await page.locator("input[type=file]").first().setInputFiles({
      name: "measurement.dat",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("bytes from a real overlay\n"),
    });

    // The file is in the volume the FUSE mount would show, and the page says
    // exactly what that means.
    await expect(card(page, "/measurement.dat")).toBeVisible();
    const notice = page.getByTestId("upload-notice");
    await expect(notice).toHaveText(
      'File uploaded to local machine; click "Publish now" to push it to the federation',
    );
    await expect(line).toHaveAttribute("data-durability", "staged");
    await expect(line).toContainText("on this machine only");

    // And the seal, for real: fence, freeze, walk, upload, flip.
    const button = page.getByTestId("publish-button");
    await expect(button).toHaveAttribute("data-publish-state", "ready");
    await button.click();
    await expect(page.getByTestId("publish-status")).toHaveAttribute("data-job-state", "done");
    await expect(line).toHaveAttribute("data-durability", "published");
    await expect(line).toContainText("in the federation");
  });
});
