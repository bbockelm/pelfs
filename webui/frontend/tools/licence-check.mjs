#!/usr/bin/env node
// The licence guard, in the one place it can actually run: over the lockfile
// and the resolved production closure.
//
// Why it exists. @svar-ui/* is MIT. The RETIRED generation of these same
// components was published under bare `wx-*` names and is GPLv3 --
// wx-react-gantt@1.3.1 still carries "license": "GPLv3" on the registry
// today, with a deprecation notice pointing at the @svar-ui replacement.
// pelfs is Apache-2.0 and the bundle is inside the shipped binary, so a
// `wx-*` package appearing in the tree -- by a dependency change, an alias,
// or an unscoped name in a version bump -- is a relicensing event disguised
// as a version bump. That is a build failure, not a review comment.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const PERMISSIVE = new Set([
  "MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
  "0BSD", "Unlicense", "CC0-1.0", "BlueOak-1.0.0", "MIT-0", "Python-2.0",
]);

let failed = false;
const fail = (m) => {
  console.error("licence-check: " + m);
  failed = true;
};

// 1. No wx-* package anywhere in the lockfile, dev or prod. The lockfile is
//    the right place to look: it names every resolved package, including the
//    ones an alias hides from package.json.
function resolvedNames(lockText) {
  const names = new Set();
  for (const m of lockText.matchAll(/^\s{2,}'?((?:@[^/'\s]+\/)?[a-zA-Z0-9._-]+)@[^:'\s]+'?:/gm)) {
    names.add(m[1]);
  }
  // aliases too: `some-name: npm:wx-react-gantt@1.3.1`
  for (const m of lockText.matchAll(/npm:((?:@[^/'\s]+\/)?[a-zA-Z0-9._-]+)@/g)) names.add(m[1]);
  return names;
}

// A guard nobody has seen fire is a guard nobody trusts, so it is exercised
// against a synthetic lockfile on every run. This costs microseconds and
// catches the failure mode that matters: a regex that quietly stops matching
// after a pnpm lockfile format change, leaving a green job and no guard.
{
  const synthetic = [
    "packages:",
    "  wx-react-gantt@1.3.1:",
    "    resolution: {integrity: sha512-x}",
    "  '@svar-ui/react-filemanager@2.6.0':",
    "    resolution: {integrity: sha512-y}",
    "  filemanager: npm:wx-react-filemanager@1.0.0",
  ].join("\n");
  const found = [...resolvedNames(synthetic)].filter((n) => /^wx-/.test(n)).sort();
  const want = ["wx-react-filemanager", "wx-react-gantt"];
  if (found.join(",") !== want.join(",")) {
    fail(
      `SELF-TEST FAILED: the wx-* detector found [${found}] in a lockfile that contains ` +
        `[${want}]. The lockfile format probably changed; fix the detector before trusting this job.`,
    );
  }
}

const lock = readFileSync("pnpm-lock.yaml", "utf8");
const names = resolvedNames(lock);
const wx = [...names].filter((n) => /^wx-/.test(n));
if (wx.length) {
  fail(
    "GPLv3 `wx-*` package(s) in pnpm-lock.yaml: " +
      wx.join(", ") +
      "\n  The wx-* generation of the SVAR components is GPLv3; pelfs is Apache-2.0 and\n" +
      "  the bundle ships inside the binary. Use the MIT @svar-ui/* packages instead.",
  );
} else {
  console.log(`licence-check: no wx-* packages in the lockfile (${names.size} resolved packages checked)`);
}

// 2. Every package in the PRODUCTION closure -- what actually ships -- has a
//    permissive licence.
function pnpm(args) {
  const via = process.env.npm_execpath;
  return via
    ? execFileSync(process.execPath, [via, ...args], { encoding: "utf8", maxBuffer: 64 << 20 })
    : execFileSync("pnpm", args, { encoding: "utf8", maxBuffer: 64 << 20 });
}
const byLicence = JSON.parse(pnpm(["licenses", "list", "--prod", "--json"]));
let n = 0;
for (const [licence, list] of Object.entries(byLicence)) {
  for (const p of list) {
    n++;
    if (!PERMISSIVE.has(licence)) {
      fail(`${p.name}@${p.versions.join(",")} is ${licence}, which is not on the permissive allowlist`);
    }
  }
}
if (!failed) console.log(`licence-check: ${n} bundled packages, all permissive`);
process.exit(failed ? 1 : 0);
