import {
  MODE,
  card,
  expect,
  openPelfs,
  resetHooks,
  test,
  testHook,
  watchOffLoopback,
} from "./pelfs";

/**
 * NOTHING LEAVES 127.0.0.1, FOR A WHOLE SESSION.
 *
 * This is a standing form of a U0 measurement, and it is the assertion that
 * keeps a design decision from rotting into a comment. The SVAR theme
 * defaults `fonts={true}`, which renders
 *
 *   <link rel="preconnect" href="https://cdn.svar.dev">
 *   <link rel="stylesheet" href="https://cdn.svar.dev/fonts/wxi/wx-icons.css">
 *
 * and its default icon callback builds
 * `https://cdn.svar.dev/icons/filemanager/vivid/<size>/<ext>.svg` per file --
 * so the CDN would learn, per session, which file extensions a physicist is
 * looking at, and the tool would be unusable on an air-gapped or
 * firewall-restricted machine. `<Willow fonts={false}>` and `icons="simple"`
 * turn both off, vite.config.ts's plugin refuses a theme element that leaves
 * fonts on, and internal/webui's Go test scans the built CSS and HTML. This
 * closes the last gap: a URL built at RUNTIME, in JavaScript, which no static
 * scan can see.
 *
 * The other reason to run it over a whole session rather than a page load:
 * the requests that would be built at runtime are the per-file ones, and a
 * page load with no directory open makes none of them.
 */
test("no request leaves loopback during a full session", async ({ page, session, playwright }) => {
  const off = watchOffLoopback(page);
  const request = await playwright.request.newContext();

  await openPelfs(page, session);

  if (MODE === "browse") {
    await expect(page.getByTestId("durability")).toBeVisible();
    await testHook(request, session, { staged_files: 2, staged_bytes: 8192 });
    await expect(page.getByTestId("durability")).toHaveAttribute("data-durability", "staged");
    await page.getByTestId("publish-button").click();
    await expect(page.getByTestId("publish-status")).toHaveAttribute("data-job-state", "done");
    await resetHooks(request, session);
  } else {
    // The file manager, with files on the screen: this is where the default
    // icon callback would have fired once per extension.
    await expect(page.getByTestId("pelfs-shell")).toBeVisible();
    await expect(card(page, "/data")).toBeVisible();
    await card(page, "/data").dblclick();
    await expect(card(page, "/data/sample.root")).toBeVisible();
  }

  // Polled rather than slept on: a late request gets its chance to appear,
  // and the first one that does fails the test.
  await expect(async () => {
    expect(off, `requests off loopback: ${off.join(", ")}`).toHaveLength(0);
  }).toPass({ timeout: 3000 });
  await request.dispose();
});
