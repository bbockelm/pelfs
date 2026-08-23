import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The probe's own build. Separate from vite.config.ts so the probe harness
// can never end up in the shipped bundle, and so its output never lands in
// internal/webui/dist.
//
// The offline-assets plugin is deliberately absent: the probe's whole job is
// to observe what the component does on the wire, including the requests the
// production config forbids.
export default defineConfig({
  root: __dirname,
  plugins: [react()],
  base: "./",
  build: { outDir: "../.probe-dist", emptyOutDir: true, sourcemap: false, target: "es2022" },
});
