import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// The bundle lands in internal/webui/dist, which is committed and embedded.
// It is NOT written under webui/frontend, because a build artefact that lives
// next to its sources is one `.gitignore` mistake away from not being
// committed at all -- and this one has to be.
const OUT = "../../internal/webui/dist";

/**
 * Two checks that keep the embedded UI able to run with no network.
 *
 * The U0 probe caught SVAR reaching off loopback in two ways:
 *   - the theme components (Willow/Material/WillowDark) default fonts={true},
 *     which renders <link rel=preconnect href=https://cdn.svar.dev> and
 *     <link rel=stylesheet href=https://cdn.svar.dev/fonts/wxi/wx-icons.css>;
 *   - the default icon callback builds
 *     https://cdn.svar.dev/icons/filemanager/vivid/<size>/<ext>.svg per file.
 * With fonts={false} and icons="simple" the page makes ZERO requests off
 * loopback (measured). These checks are what keep that true.
 *
 * Why the checks are shaped this way: a remote URL inside a JS chunk cannot
 * be judged statically -- the strings above survive tree-shaking as dead
 * constants, and so do a dozen XML namespace URIs. So:
 *   - CSS and HTML outputs ARE scanned, because url()/@import/src/href in
 *     them are unconditional fetches;
 *   - the JS risk is closed at its source instead, by refusing a theme
 *     element that has not turned fonts off;
 *   - and the runtime assertion lives in the Playwright suite, which fails
 *     if the page requests anything off 127.0.0.1.
 */
function offlineAssets() {
  const remote = /(?:url\(\s*['"]?|@import\s+['"]|\bsrc=['"]|\bhref=['"])(https?:)?\/\/(?!localhost|127\.0\.0\.1)[^'")\s]+/g;
  const themeOpen = /<\s*(Willow|WillowDark|Material)\b([^>]*)>/g;

  function walk(dir: string, out: string[] = []): string[] {
    for (const e of readdirSync(dir)) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) walk(p, out);
      else out.push(p);
    }
    return out;
  }

  return {
    name: "pelfs-offline-assets",
    buildStart() {
      const bad: string[] = [];
      for (const f of walk("src").filter((f) => /\.tsx?$/.test(f))) {
        const text = readFileSync(f, "utf8");
        for (const m of text.matchAll(themeOpen)) {
          if (!/fonts\s*=\s*\{\s*false\s*\}/.test(m[2])) {
            bad.push(`${f}: <${m[1]}> without fonts={false}`);
          }
        }
      }
      if (bad.length) {
        throw new Error(
          "pelfs-offline-assets: a SVAR theme element leaves fonts on, which injects\n" +
            "a stylesheet link to https://cdn.svar.dev. The UI is served from a Go binary\n" +
            "on loopback and must load nothing from the network. Pass fonts={false}.\n" +
            bad.map((b) => "  " + b).join("\n"),
        );
      }
    },
    writeBundle(_: unknown, bundle: Record<string, { type: string; source?: unknown; code?: string; fileName: string }>) {
      const bad: string[] = [];
      for (const [name, chunk] of Object.entries(bundle)) {
        if (!/\.(css|html)$/.test(name)) continue;
        const text = typeof chunk.source === "string" ? chunk.source : (chunk.code ?? "");
        for (const m of text.matchAll(remote)) bad.push(`${name}: ${m[0].slice(0, 140)}`);
      }
      if (bad.length) {
        throw new Error(
          "pelfs-offline-assets: a built stylesheet or page fetches from a remote origin:\n" +
            bad.map((b) => "  " + b).join("\n"),
        );
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), offlineAssets()],
  // Relative asset URLs: the bundle is served from the binary's root today,
  // but a future sub-path mount must not need a rebuild.
  base: "./",
  build: {
    outDir: OUT,
    emptyOutDir: true,
    // Byte-reproducibility is what makes the regenerate-and-diff gate
    // trustworthy, so nothing that varies per machine or per run is allowed
    // into the output: no sourcemaps (they carry absolute paths), no build
    // id, no timestamp, asset names hashed from content only.
    sourcemap: false,
    target: "es2022",
    reportCompressedSize: true,
  },
});
