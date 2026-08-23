#!/usr/bin/env node
// Records the SVAR component's request sequence as a fixture, so the
// protocol can be replayed in Go forever without Node in CI.
//
// This is layer 5 of docs/design-webui.md's testing plan: "Run the real
// component against a logging stub server once, by hand, on a machine with
// Node; commit the recording as a fixture; and make the Go test replay it
// against the real handlers and assert the responses." Same trick as
// internal/hostile/testdata/corpus/ -- a bug report that cannot rot.
//
// Run:  pnpm probe:record
import { chromium } from "@playwright/test";
import { writeFileSync } from "node:fs";

const base = `http://127.0.0.1:${process.env.PORT || 8781}`;
const OUT = "../../internal/webui/testdata/svar-contract/recording.json";

const drain = async () => {
  const l = await (await fetch(`${base}/__log`)).json();
  await fetch(`${base}/__reset?scenario=lazy`);
  return l;
};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
const external = new Set();
page.on("request", (r) => {
  const u = new URL(r.url());
  if (u.hostname !== "127.0.0.1") external.add(`${r.method()} ${u.origin}${u.pathname}`);
});
await fetch(`${base}/__reset?scenario=lazy`);

const steps = [];
async function step(name, gesture, note, fn) {
  await fn();
  steps.push({ step: name, gesture, note, requests: await drain() });
  console.log(`${name}: ${steps.at(-1).requests.length} request(s)`);
}

await step("boot", "load the page", "the root listing and the drive info, and nothing else", async () => {
  await page.goto(base + "/", { waitUntil: "networkidle" });
  await page.waitForFunction(() => window.__probe && window.__probe.ready, null, { timeout: 30000 });
});
await step("open-folder", 'double-click the "/dir-0" card', "one listing for the folder navigated into", async () => {
  await page.locator('[data-id=":/dir-0"]').first().dblclick();
  await page.waitForFunction(() => document.querySelectorAll(".wx-breadcrumbs [data-id]").length > 1);
});
await step("open-nested-folder", 'double-click "/dir-0/dir-1"', "the id is the full path, percent-encoded into ONE path segment", async () => {
  await page.locator('[data-id=":/dir-0/dir-1"]').first().dblclick();
  await page.waitForFunction(() => document.querySelectorAll(".wx-breadcrumbs [data-id]").length > 2);
});
await step("revisit-loaded-folder", "breadcrumb back, then re-open /dir-0", "NO request: a loaded folder is cached in the store for the life of the page", async () => {
  await page.locator('.wx-breadcrumbs [data-id=":/"]').first().click();
  await page.locator('[data-id=":/dir-0"]').first().dblclick();
  await page.waitForTimeout(400);
});
await step("refresh", "click the breadcrumb refresh icon", "the only gesture that re-lists a folder the store already has", async () => {
  await page.locator(".wx-breadcrumbs .wxi-refresh").first().click();
  await page.waitForTimeout(400);
});
await step("create-folder", '"Add new folder"', "POST files/{parent}; the response id is authoritative, the client renames to match", async () => {
  await page.evaluate(() =>
    window.__probe.api.exec("create-file", { parent: "/dir-0", file: { name: "new-folder", type: "folder" } }));
  await page.waitForTimeout(300);
});
await step("rename", "Rename (Ctrl+R)", "PUT files/{id} with operation=rename", async () => {
  await page.evaluate(() =>
    window.__probe.api.exec("rename-file", { id: "/dir-0/file-0.txt", name: "renamed.txt" }));
  await page.waitForTimeout(300);
});
await step("copy", "Copy then Paste (Ctrl+C, Ctrl+V)", "PUT files (no id) with operation=copy and a batch of ids", async () => {
  await page.evaluate(() =>
    window.__probe.api.exec("copy-files", { ids: ["/dir-0/file-1.txt"], target: "/dir-0/dir-2" }));
  await page.waitForTimeout(300);
});
await step("move", "drag-and-drop, or Cut then Paste", "PUT files with operation=move", async () => {
  await page.evaluate(() =>
    window.__probe.api.exec("move-files", { ids: ["/dir-0/file-2.txt"], target: "/dir-0/dir-1" }));
  await page.waitForTimeout(300);
});
await step("delete", "Delete", "DELETE files with a batch of ids IN THE BODY, not in the path", async () => {
  await page.evaluate(() =>
    window.__probe.api.exec("delete-files", { ids: ["/dir-0/file-3.txt"] }));
  await page.waitForTimeout(300);
});
await step("upload", "Upload file", "ONE multipart POST via fetch: no XHR, no progress events, no chunking, no resume", async () => {
  await page.evaluate(async () => {
    const f = new File([new Uint8Array(4096)], "payload.bin", { type: "application/octet-stream" });
    await window.__probe.api.exec("create-file", { parent: "/dir-0", file: { name: "payload.bin", file: f } });
  });
  await page.waitForTimeout(500);
});
await step("search", 'type "file" in the toolbar search box', "NO request: search is client-side over what is already loaded, so a capped listing means a partial search", async () => {
  await page.locator(".wx-search-input .wx-text").first().fill("file");
  await page.waitForTimeout(600);
});
await step("as-shipped-provider", "the component's own RestDataProvider, with setHeaders() called", "THE DEFECT: no X-Pelfs-Session header, and text/plain on the mutation. RestDataProvider.send() ignores this._customHeaders and sets no content type.", async () => {
  await page.evaluate(async () => {
    await window.__probe.shipped.loadFiles("/dir-2");
    await window.__probe.shipped.getHandlers()["create-file"].handler({
      parent: "/dir-2", file: { name: "as-shipped", type: "folder" },
    });
  });
  await page.waitForTimeout(400);
});

writeFileSync(
  OUT,
  JSON.stringify(
    {
      what: "The wire protocol of @svar-ui/react-filemanager, recorded from the real component.",
      why: "docs/design-webui.md, 'Testing' layer 5: record once with Node, replay forever in Go.",
      recordedAt: new Date().toISOString(),
      browser: `chromium ${browser.version()}`,
      component: {
        "@svar-ui/react-filemanager": "2.6.0",
        "@svar-ui/filemanager-data-provider": "2.6.0",
        react: "19.1.1",
      },
      provider:
        "webui/frontend/src/api/provider.ts (PelfsDataProvider), except the last step, which uses the component's own RestDataProvider",
      apiBase: "/api/v1",
      externalRequests: [...external].sort(),
      steps,
    },
    null,
    2,
  ) + "\n",
);
console.log(`recorded ${steps.length} steps -> ${OUT}`);
await browser.close();
