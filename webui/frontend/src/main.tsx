import { createRoot } from "react-dom/client";
import { App } from "./App";
// all.css, NOT style.css. style.css is the file manager's own rules only: it
// leaves every base --wx-* token undefined and ships no rules for the menu,
// the modal, the segmented view switch or the uploader's hidden file input,
// all of which this component builds out of its sibling packages. See
// vite.config.ts's dropRemoteFontFaces for what makes the complete file
// loopback-safe, and src/brand/brand.css for the tokens it is given.
import "@svar-ui/react-filemanager/all.css";
import "./brand/brand.css";
import "./ui/app.css";
// LAST, and that is the point of the position: icons.css draws the file
// manager's own `wxi-*` glyphs, which arrive from nowhere else -- all.css
// carries the theme's text fonts and not one icon rule, because the icon font
// lives at cdn.svar.dev and the UI loads nothing off loopback. Importing it
// after the component's stylesheet means an equal-specificity rule of ours
// wins instead of losing a coin toss. See the file's header for why this is
// CSS rather than the component's `icons` prop.
import "./ui/icons.css";

const el = document.getElementById("root");
if (el) createRoot(el).render(<App />);
