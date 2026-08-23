import { MODE, card, expect, openPelfs, test } from "./pelfs";

// The example spec: one file that proves the harness end to end.
//
// It runs in both of the harness's modes and asserts what is true of each:
//
//   browse mode  `pelfs browse` serving M1's hand-written connection page.
//                Selectors are that page's own data-testid hooks
//                (cmd/pelfs/browse.html), which is the contract its header
//                comment promises: "Every element a test asserts on carries
//                data-testid".
//   embed mode   the committed React bundle served by internal/webui, against
//                the mock JSON API in internal/webui/mockapi_test.go.
//                Selectors are webui/frontend/src's own hooks.
//
// It used to assert, in embed mode, that the page showed its "the data plane
// is not built yet" placeholder. That placeholder is now the FAILURE state --
// there is an API to talk to -- so asserting on it would have made a broken
// data plane look like a passing test.
const volume = process.env.PELFS_WEBUI_VOLUME;

test("the page is served, and names the volume it is serving", async ({ page, session }) => {
  await openPelfs(page, session);

  if (MODE === "browse") {
    await expect(page.getByTestId("volume")).toBeVisible();
    if (volume) await expect(page.getByTestId("volume")).toContainText(volume);
    // The wordmark: "pel" in the text colour, "fs" in the brand blue.
    await expect(page.locator("h1 .fs")).toHaveText("fs");
  } else {
    await expect(page.getByTestId("pelfs-shell")).toBeVisible();
    // A real listing, from a real request that carried the session header.
    await expect(card(page, "/README.txt")).toBeVisible();
    // And the volume the API named, in the header.
    await expect(page.getByTestId("pelfs-brand")).toContainText("pelican://");
  }
});

test("the mark is used with permission, and the page says what pelfs is not", async ({ page }) => {
  test.skip(
    MODE !== "embed",
    "the brand assets are in the React bundle; M1's page is hand-written HTML with its own header",
  );
  // No session on purpose: the brand, the disclaimer and the notices link are
  // page furniture and must be there even when the app cannot start.
  await page.goto("/");

  const brand = page.getByTestId("pelfs-brand");
  await expect(brand).toBeVisible();
  // The Pelican mark, unmodified, beside the wordmark. Nothing is drawn on
  // top of it, which is why nothing about it can be got wrong.
  await expect(brand.locator("img")).toHaveAttribute("src", /PelicanPlatformLogo_Icon\.png$/);
  await expect(brand).toContainText("pelfs");

  // A borrowed mark without this line is a claim nobody made deliberately.
  await expect(page.getByTestId("pelfs-disclaimer")).toContainText(
    /not.*an official Pelican Platform product/i,
  );

  // The MIT notices have to be reachable from the UI, because the
  // distribution is a Go binary with the bundle inside it.
  const notices = await page.request.get(new URL("third_party.txt", page.url()).toString());
  expect(notices.ok()).toBeTruthy();
  expect(await notices.text()).toContain("@svar-ui/react-filemanager");
});

test("the page loads nothing off loopback on first paint", async ({ page, session }) => {
  // The measurement the U0 probe made, as a standing assertion. The default
  // SVAR theme injects a stylesheet link to cdn.svar.dev and its default icon
  // callback builds CDN URLs per file extension; both are off, and this is
  // what notices if a rebuild turns them back on. It is worth running against
  // M1's page too: a hand-written page can grow a font link just as easily.
  // The whole-session version, which is where a runtime-built icon URL would
  // appear, is loopback.spec.ts.
  const offHost: string[] = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.protocol.startsWith("http") && u.hostname !== "127.0.0.1" && u.hostname !== "localhost") {
      offHost.push(`${r.method()} ${u.origin}${u.pathname}`);
    }
  });
  await openPelfs(page, session);
  // Poll rather than sleep: give a late request a chance to appear, and fail
  // on the first one that does. There is no setTimeout anywhere in this suite.
  await expect(async () => {
    expect(offHost, `requests off loopback: ${offHost.join(", ")}`).toHaveLength(0);
  }).toPass({ timeout: 3000 });
});
