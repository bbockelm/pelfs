import { defineConfig, devices } from "@playwright/test";

// The browser suite. It exists for ONE reason: the browser half of the threat
// model. SameSite, CORS preflight behaviour, Local Network Access and DNS
// rebinding are enforced by the browser, and a Go test asserting "we return
// 403" does not prove "the browser never sent it".
//
// Everything else a browser could check here -- does the grid render, does
// drag-and-drop work -- is deliberately out of scope: those failures are loud
// and immediate in manual use, while the CSRF ones are silent.
//
// The server is NOT started by Playwright. scripts/webui-playwright.sh starts
// it, because the thing worth driving is the real `pelfs browse` against a
// real federation stub, and the port and the single-use bootstrap token are
// chosen at runtime. The script hands both over in the environment:
//
//   PELFS_WEBUI_URL        the ephemeral URL, e.g. http://127.0.0.1:49731/
//   PELFS_WEBUI_BOOTSTRAP  the single-use bootstrap token, if the server issued one
//   PELFS_WEBUI_MODE       "browse" (the real binary) or "embed" (bundle only)
const baseURL = process.env.PELFS_WEBUI_URL;

// The attacker origin for the cross-site and DNS-rebinding specs.
// --host-resolver-rules is the whole reason the rebinding defence is testable
// without touching /etc/hosts: the page's own requests then carry
// `Host: attacker.test:PORT`, which is exactly the header the allowlist must
// reject with 421.
const attackerHost = process.env.PELFS_WEBUI_ATTACKER_HOST || "attacker.test";

export default defineConfig({
  testDir: "tests",
  // NO RETRIES, on purpose. A flaky browser gate teaches people to rerun CI
  // until it is green, which is worse than no gate: the next real failure
  // gets rerun too. Determinism comes from Playwright's expect-with-timeout
  // polling instead of fixed sleeps -- there is not one setTimeout in the
  // suite -- and if a spec is genuinely racy the fix is the spec, not a
  // retry count. If a test ever needs a retry to pass, that is the bug.
  retries: 0,
  forbidOnly: !!process.env.CI,
  fullyParallel: false, // one server, one volume: parallel specs would share state
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [["github"], ["list"]] : [["list"]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "same-origin",
      use: { ...devices["Desktop Chrome"], channel: undefined },
      testIgnore: /cross-origin/,
    },
    {
      // A second project rather than a second context, because
      // --host-resolver-rules is a browser-launch flag: it cannot be set per
      // context. Specs here load their page from http://attacker.test:PORT/,
      // which is a genuinely different origin AND a different Host header, so
      // one project covers both the cross-site and the rebinding cases.
      name: "cross-origin",
      testMatch: /cross-origin/,
      use: {
        ...devices["Desktop Chrome"],
        channel: undefined,
        launchOptions: {
          args: [`--host-resolver-rules=MAP ${attackerHost} 127.0.0.1`],
        },
      },
    },
  ],
});
