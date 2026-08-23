import { MODE, card, expect, openPelfs, test } from "./pelfs";

// The example spec: one file that proves the harness end to end.
//
// SINCE THE WIRING PASS, `/` IS THE SAME PAGE IN BOTH MODES: the committed
// React bundle, served by `pelfs browse` from its route table or by
// internal/webui's test server. So this file no longer forks on which page it
// is looking at -- only on what that page can be expected to CONTAIN, which is
// a property of the volume behind it:
//
//   browse mode  a real v2 volume against a fakeorigin federation stub. It is
//                empty, so there is no named file to assert on, and the volume
//                the header names is the harness's own prefix.
//   embed mode   the mock JSON API in internal/webui/mockapi_test.go, which
//                seeds a known tree -- so a listing with /README.txt in it is
//                an assertion here and cannot be one there.
//
// The connection page, which used to be what browse mode served here, has its
// own address and its own file: connect.spec.ts.
const volume = process.env.PELFS_WEBUI_VOLUME;

test("the page is served, and names the volume it is serving", async ({ page, session }) => {
  await openPelfs(page, session);

  await expect(page.getByTestId("pelfs-shell")).toBeVisible();
  // The wordmark, with the "fs" in the brand blue. It is in the bundle in
  // both modes, which is the whole point of the wiring pass.
  const brand = page.getByTestId("pelfs-brand");
  await expect(brand).toBeVisible();
  await expect(brand).toContainText("pelfs");

  if (MODE === "browse") {
    // The volume this run actually created, rather than a hard-coded string.
    if (volume) await expect(brand).toContainText(volume);
    // A real volume, so a real (empty) grid rather than a named file. What
    // matters is that the data plane answered at all: without the provider's
    // session header the app shows its "no data plane" banner instead.
    await expect(page.getByTestId("pelfs-status")).toBeHidden();
    await expect(page.getByTestId("durability")).toBeVisible();
  } else {
    // A real listing, from a real request that carried the session header.
    await expect(card(page, "/README.txt")).toBeVisible();
    await expect(brand).toContainText("pelican://");
  }
});

test("the mark travels with the page, and the MIT notices are reachable from it", async ({
  page,
}) => {
  // No session on purpose: the brand and the notices link are page furniture
  // and must be there even when the app cannot start.
  //
  // There used to be a third assertion here, on a footer disclaimer saying
  // what pelfs is not. The footer is gone -- the Pelican Project's PI, whose
  // mark it is, asked for it off the page -- and a spec that asserts a removed
  // element is deleted rather than weakened, so that assertion went with it.
  // The attribution itself did not: it ships in brand/NOTICE.txt beside the
  // asset, which internal/webui/webui_test.go asserts is served.
  await page.goto("/");

  const brand = page.getByTestId("pelfs-brand");
  await expect(brand).toBeVisible();
  // The Pelican mark, unmodified, beside the wordmark. Nothing is drawn on
  // top of it, which is why nothing about it can be got wrong.
  await expect(brand.locator("img")).toHaveAttribute("src", /PelicanPlatformLogo_Icon\.png$/);

  // The MIT notices have to be reachable from the UI, because the
  // distribution is a Go binary with the bundle inside it -- so both the link
  // and the route it points at are asserted.
  await expect(page.getByTestId("pelfs-notices-link")).toHaveAttribute(
    "href",
    /third_party\.txt$/,
  );
  const notices = await page.request.get(new URL("third_party.txt", page.url()).toString());
  expect(notices.ok()).toBeTruthy();
  expect(await notices.text()).toContain("@svar-ui/react-filemanager");
});

test("the page loads nothing off loopback on first paint", async ({ page, session }) => {
  // The measurement the U0 probe made, as a standing assertion. The default
  // SVAR theme injects a stylesheet link to cdn.svar.dev and its default icon
  // callback builds CDN URLs per file extension; both are off, and this is
  // what notices if a rebuild turns them back on. The whole-session version,
  // which is where a runtime-built icon URL would appear, is loopback.spec.ts.
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
