#!/usr/bin/env node
// U0: the probe that gates M4.
//
// Two questions decide whether @svar-ui/react-filemanager can be used on a
// pelfs volume at all, and neither is answerable from the documentation:
//
//   1. Does it load a directory LAZILY, or does it want the whole tree up
//      front? A volume with 100k files must not become one request.
//   2. Does it VIRTUALIZE a large directory's rendering?
//
// It answers both by driving the real component against the logging stub,
// and it sweeps directory sizes so the answer to (2) comes with the number
// the JSON API's response cap should be set to.
//
// Run:  pnpm probe        (builds the harness, starts the stub, runs this)
import { chromium } from "@playwright/test";
import { writeFileSync } from "node:fs";

const base = `http://127.0.0.1:${process.env.PORT || 8781}`;
const out = { measuredAt: new Date().toISOString(), browser: null, lazy: {}, virtualization: {} };
const external = new Set();

const reset = (scenario, size) =>
  fetch(`${base}/__reset?scenario=${scenario}${size ? `&size=${size}` : ""}`).then((r) => r.json());
const requests = async () =>
  (await (await fetch(`${base}/__log`)).json()).map((r) => `${r.method} ${r.path}${r.query}`);

const browser = await chromium.launch();
out.browser = `chromium ${browser.version()}`;
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
page.on("request", (r) => {
  const u = new URL(r.url());
  if (u.hostname !== "127.0.0.1") external.add(`${r.method()} ${u.origin}${u.pathname}`);
});

const measure = () =>
  page.evaluate(() => {
    const scroller = document.querySelector(".wx-cards") || document.querySelector('[class*="wx-table"]');
    return {
      cards: document.querySelectorAll(".wx-cards .wx-item").length,
      rows: document.querySelectorAll('[class*="wx-row"]').length,
      domNodes: document.getElementsByTagName("*").length,
      scrollHeightPx: scroller ? scroller.scrollHeight : null,
      clientHeightPx: scroller ? scroller.clientHeight : null,
      jsHeapMB: performance.memory ? Math.round(performance.memory.usedJSHeapSize / 1e6) : null,
    };
  });

// ---- question 1: lazy loading ------------------------------------------
await reset("lazy");
await page.goto(base + "/", { waitUntil: "networkidle" });
await page.waitForFunction(() => window.__probe && window.__probe.ready, null, { timeout: 30000 });
out.lazy.atBoot = { requests: await requests(), dom: await measure() };

await page.locator('[data-id=":/dir-0"]').first().dblclick();
await page.waitForFunction(() => document.querySelectorAll('.wx-breadcrumbs [data-id]').length > 1,
  null, { timeout: 15000 });
out.lazy.afterOpeningOneFolder = { requests: await requests() };

await page.locator('[data-id=":/dir-0/dir-1"]').first().dblclick();
await page.waitForFunction(() => document.querySelectorAll('.wx-breadcrumbs [data-id]').length > 2,
  null, { timeout: 15000 });
out.lazy.afterOpeningANestedFolder = { requests: await requests() };

await page.locator('.wx-breadcrumbs [data-id=":/"]').first().click();
await page.locator('[data-id=":/dir-0"]').first().dblclick();
await page.waitForTimeout(300);
out.lazy.afterRevisitingALoadedFolder = { requests: await requests() };
out.lazy.verdict =
  out.lazy.atBoot.requests.length === 2 && out.lazy.afterOpeningANestedFolder.requests.length > 2
    ? "LAZY: one listing per directory, on navigation into it"
    : "NOT LAZY -- investigate before building M4";

// ---- question 2: virtualization, and the size sweep -------------------
const sizes = [1000, 5000, 20000, 50000, 100000];
out.virtualization.sweep = [];
for (const size of sizes) {
  await reset("big", size);
  const p = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await p.goto(base + "/", { waitUntil: "networkidle" });
  await p.waitForFunction(() => window.__probe && window.__probe.ready, null, { timeout: 60000 });
  const t0 = Date.now();
  await p.locator('[data-id=":/big"]').first().dblclick();
  await p
    .waitForFunction((n) => document.querySelectorAll(".wx-cards .wx-item").length >= n, size,
      { timeout: 600000 })
    .catch(() => {});
  const openMs = Date.now() - t0;
  const cards = await p.evaluate(() => {
    const s = document.querySelector(".wx-cards");
    return {
      cards: document.querySelectorAll(".wx-cards .wx-item").length,
      domNodes: document.getElementsByTagName("*").length,
      jsHeapMB: performance.memory ? Math.round(performance.memory.usedJSHeapSize / 1e6) : null,
      scrollHeightPx: s ? s.scrollHeight : null,
      clientHeightPx: s ? s.clientHeight : null,
    };
  });
  const t1 = Date.now();
  await p.locator(".wx-modes .wx-segment").first().click();
  await p
    .waitForFunction((n) => document.querySelectorAll('[class*="wx-row"]').length >= n, size,
      { timeout: 600000 })
    .catch(() => {});
  const tableMs = Date.now() - t1;
  const table = await p.evaluate(() => ({
    rows: document.querySelectorAll('[class*="wx-row"]').length,
    domNodes: document.getElementsByTagName("*").length,
    jsHeapMB: performance.memory ? Math.round(performance.memory.usedJSHeapSize / 1e6) : null,
  }));
  // Scrolling to the bottom: a virtualized grid would fetch or re-render
  // here; a non-virtualized one has already rendered everything.
  const before = await p.evaluate(() => document.getElementsByTagName("*").length);
  await p.evaluate(() => {
    const el = document.querySelector('[class*="wx-table"]') || document.querySelector(".wx-cards");
    if (el) el.scrollTop = el.scrollHeight;
  });
  await p.waitForTimeout(1000);
  const after = await p.evaluate(() => document.getElementsByTagName("*").length);
  out.virtualization.sweep.push({
    entries: size, cardsMode: { openMs, ...cards }, tableMode: { tableMs, ...table },
    domNodesBeforeScroll: before, domNodesAfterScroll: after,
    requestsAfterScroll: (await requests()).length,
  });
  console.log(JSON.stringify(out.virtualization.sweep.at(-1)));
  await p.close();
}
const worst = out.virtualization.sweep.at(-1);
out.virtualization.verdict =
  worst.cardsMode.cards >= worst.entries
    ? `NOT VIRTUALIZED: ${worst.entries} entries produced ${worst.cardsMode.cards} card elements ` +
      `and ${worst.cardsMode.domNodes} DOM nodes. The API's response cap is the design, not a fallback.`
    : "VIRTUALIZED";

out.externalRequests = [...external].sort();
writeFileSync("../../internal/webui/testdata/svar-contract/u0-measurements.json", JSON.stringify(out, null, 2));
console.log("\n" + out.lazy.verdict + "\n" + out.virtualization.verdict);
console.log("external requests: " + (out.externalRequests.length ? out.externalRequests.join(", ") : "none"));
await browser.close();
