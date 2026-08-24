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

/**
 * THE VENDOR'S BASE STYLESHEET, MINUS ITS WEB FONTS.
 *
 * @svar-ui/react-filemanager ships TWO stylesheets and the difference is not
 * cosmetic. `style.css` is the file manager's OWN rules only: it references
 * ~30 `--wx-*` custom properties and defines none of the base ones, and it
 * contains no rules at all for the widgets the component builds out of its
 * siblings -- the dropdown menu behind "Add New", the rename/confirm modal,
 * the segmented view switch, the checkbox, the button, the uploader's hidden
 * file input. `all.css` (the package's `./all.css` export, the same build with
 * @svar-ui/react-core, -grid, -menu and -uploader in it) is the complete one.
 *
 * The app imported `style.css`, so it shipped a file manager with
 * `--wx-background`, `--wx-border`, `--wx-color-font` and `--wx-color-primary`
 * UNDEFINED and its menus and modals unstyled. Measured, in a browser, before
 * this changed: every card was transparent, `border: var(--wx-border)` on the
 * search box resolved to `0px none` so the one text input on the page had no
 * border at all, the uploader's `<input type=file>` kept its native 253px
 * "Choose Files / No file chosen" widget in the middle of the layout because
 * the rule that hides it lives in the uploader's stylesheet, the "Add New"
 * menu rendered as bare text on top of the folder tree, and the "Enter folder
 * name" modal rendered as three unstyled controls at the bottom of the page.
 *
 * The reason it was imported that way is real, and this plugin is what makes
 * the complete file usable instead: `all.css` carries six @font-face rules
 * for Open Sans and Roboto that fetch from cdn.svar.dev. The UI is served by a
 * Go binary on loopback and must load nothing off the network -- so the rules
 * are dropped here, at build time, and the ONLY thing dropped is an @font-face
 * block whose src is remote. Everything else in the file is kept.
 *
 * A dropped @font-face is not a missing glyph: the themes' `--wx-font-family`
 * is overridden in src/brand/brand.css with the platform stack the rest of the
 * app uses, so the component and the chrome are one typeface rather than two.
 *
 * This runs BEFORE Vite's own CSS pipeline (`enforce: "pre"`), and
 * offlineAssets()'s writeBundle scan still runs after it over the built CSS --
 * so if this plugin ever stops matching, the build fails rather than quietly
 * shipping a stylesheet that phones home.
 */
function dropRemoteFontFaces() {
  // An @font-face block, and then only if a src in it is off this machine.
  const face = /@font-face\s*{[^}]*}/g;
  const remoteSrc = /url\(\s*['"]?(?:https?:)?\/\/(?!localhost|127\.0\.0\.1)/;
  return {
    name: "pelfs-drop-remote-font-faces",
    enforce: "pre" as const,
    transform(code: string, id: string) {
      if (!/\.css(\?|$)/.test(id)) return null;
      let dropped = 0;
      const out = code.replace(face, (block) => {
        if (!remoteSrc.test(block)) return block;
        dropped++;
        return "";
      });
      if (!dropped) return null;
      return { code: out, map: null };
    },
  };
}

export default defineConfig({
  plugins: [react(), dropRemoteFontFaces(), offlineAssets()],
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
