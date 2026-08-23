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
  test.skip(
    MODE !== "embed",
    "the React app is served by internal/webui; `pelfs browse` serves M1's page at / until the wiring pass",
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
    // The durability panel is above the files, not behind a tab.
    await expect(page.getByTestId("durability")).toBeVisible();
    await expect(page.getByTestId("durability-legend")).toBeVisible();
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
    await expect(cap).toContainText("6,000");
    await expect(cap).toContainText("shown in part");
    // And it names what to do instead, rather than leaving the user stuck.
    await expect(cap).toContainText("pelfs mount");
  });

  test("the partial search is admitted in words, beside the search box", async ({
    page,
    session,
  }) => {
    // Typing in the toolbar's search box fires NO request (recording.json,
    // step "search"): the store filters what it has. Combined with the cap,
    // "no results" means "not in what this tab loaded", which is a different
    // statement from "not in your volume".
    await openPelfs(page, session);
    const notice = page.getByTestId("search-scope");
    // Before anyone types: the caveat is already on the screen, as a
    // sentence, in the strip directly above the toolbar whose search box sits
    // at its left. Not a tooltip -- a tooltip does not exist on a touch
    // screen and is invisible to anyone who does not think to hover.
    await expect(notice).toBeVisible();
    await expect(notice).toHaveAttribute("data-searching", "no");
    await expect(notice).toContainText("partial by design");

    const box = page.getByPlaceholder("Search");
    await box.fill("sample");
    await expect(notice).toHaveAttribute("data-searching", "yes");
    await expect(notice).toContainText("This search is partial");
    await expect(notice).toContainText("asks the server nothing");
  });

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
    await expect(notice).toContainText("THIS MACHINE");
    await expect(notice).toContainText("invisible to the federation");
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
