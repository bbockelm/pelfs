#!/usr/bin/env node
// Generates internal/webui/third_party.txt: every package bundled into the
// UI, its version, its licence, and the full licence text.
//
// Why the full text and not just the SPDX id: MIT and BSD require the
// copyright notice and permission notice to travel WITH the distribution,
// and the distribution here is a Go binary with the bundle inside it. The
// file is embedded next to dist/ and served at /third_party.txt, which makes
// the obligation satisfiable by a user who has nothing but the binary.
//
// It is generated from `pnpm licenses list --prod --json`, so it lists the
// PRODUCTION closure -- what actually ships -- and not the build tools.
// Committed alongside dist/ so a Node-less build still has it.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const OUT = "../../internal/webui/third_party.txt";

// Anything not on this list stops the build. GPL/LGPL/AGPL are the ones that
// matter here: pelfs is Apache-2.0 and the bundle is inside the shipped
// binary, so a copyleft dependency is not a footnote, it is a relicensing
// event. The retired `wx-*` generation of these very components is GPLv3.
const PERMISSIVE = new Set([
  "MIT",
  "ISC",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "0BSD",
  "Unlicense",
  "CC0-1.0",
  "BlueOak-1.0.0",
  "MIT-0",
  "Python-2.0",
]);

// pnpm may not be on PATH at all -- the whole toolchain is reachable
// through corepack, and `go generate` goes through scripts/webui-build.sh
// which resolves it. When this script runs as a pnpm lifecycle script,
// npm_execpath points at the very pnpm that started it, which is the one
// whose store the licences must be read from.
function pnpm(args) {
  const via = process.env.npm_execpath;
  return via
    ? execFileSync(process.execPath, [via, ...args], { encoding: "utf8", maxBuffer: 64 << 20 })
    : execFileSync("pnpm", args, { encoding: "utf8", maxBuffer: 64 << 20 });
}

const raw = pnpm(["licenses", "list", "--prod", "--json"]);
const byLicence = JSON.parse(raw);

const pkgs = [];
for (const [licence, list] of Object.entries(byLicence)) {
  for (const p of list) pkgs.push({ ...p, licence });
}
pkgs.sort((a, b) => a.name.localeCompare(b.name));

const bad = pkgs.filter((p) => !PERMISSIVE.has(p.licence));
if (bad.length) {
  console.error("third-party: non-permissive or unknown licence in the bundled closure:");
  for (const p of bad) console.error(`  ${p.name}@${p.versions.join(",")}: ${p.licence}`);
  process.exit(1);
}
const wx = pkgs.filter((p) => /^wx-/.test(p.name));
if (wx.length) {
  console.error("third-party: a wx-* package is in the bundle. That generation is GPLv3:");
  for (const p of wx) console.error(`  ${p.name}@${p.versions.join(",")}`);
  process.exit(1);
}

function licenceText(dir) {
  if (!dir || !existsSync(dir)) return null;
  const names = readdirSync(dir).filter((f) =>
    /^(licen[cs]e|copying|notice)(\.(txt|md))?$/i.test(f),
  );
  for (const n of names) {
    const t = readFileSync(join(dir, n), "utf8").trim();
    if (t) return t;
  }
  return null;
}

const lines = [];
lines.push("Third-party software bundled in the pelfs browser UI");
lines.push("====================================================");
lines.push("");
lines.push("GENERATED FILE -- do not edit. Regenerate with:");
lines.push("");
lines.push("    go generate ./internal/webui");
lines.push("");
lines.push(
  "The pelfs browser UI is a JavaScript bundle compiled from the packages",
);
lines.push(
  "below and embedded in the pelfs binary (internal/webui/dist). pelfs itself",
);
lines.push(
  "is licensed under the Apache License 2.0; the packages below keep their own",
);
lines.push(
  "licences, and the notices those licences require to travel with a",
);
lines.push("distribution are reproduced in full.");
lines.push("");
lines.push(`Packages: ${pkgs.length}`);
lines.push(
  "Licences: " +
    [...new Set(pkgs.map((p) => p.licence))].sort().join(", ") +
    " (all permissive; no copyleft)",
);
lines.push("");
lines.push("Summary");
lines.push("-------");
lines.push("");
const w = Math.max(...pkgs.map((p) => p.name.length));
for (const p of pkgs) {
  lines.push(`  ${p.name.padEnd(w)}  ${p.versions.join(", ").padEnd(10)}  ${p.licence}`);
}
lines.push("");
lines.push("Licence texts");
lines.push("-------------");
const seen = new Map();
const noText = [];
for (const p of pkgs) {
  const text = licenceText(p.paths && p.paths[0]);
  const id = `${p.name}@${p.versions.join(",")}`;
  if (!text) {
    noText.push(`${id} (declares ${p.licence})`);
    continue;
  }
  if (!seen.has(text)) seen.set(text, []);
  seen.get(text).push(id);
}
for (const [text, owners] of seen) {
  lines.push("");
  lines.push("-".repeat(72));
  lines.push(`Applies to: ${owners.join(", ")}`);
  lines.push("-".repeat(72));
  lines.push("");
  lines.push(text);
}
if (noText.length) {
  lines.push("");
  lines.push("-".repeat(72));
  lines.push("Declared licence, but no licence file published in the package");
  lines.push("-".repeat(72));
  lines.push("");
  lines.push("These packages declare their licence in package.json but publish no");
  lines.push("licence file of their own. Every one of them is part of a project whose");
  lines.push("licence text IS reproduced above (the @svar-ui packages are all published");
  lines.push("by XB Software Sp. z o.o. under the MIT text shown above); the declared");
  lines.push("identifier is recorded here so the gap is visible rather than papered over.");
  lines.push("");
  for (const n of noText) lines.push(`  ${n}`);
}
lines.push("");
writeFileSync(OUT, lines.join("\n"));
console.log(`third-party: ${pkgs.length} packages -> ${OUT}`);
