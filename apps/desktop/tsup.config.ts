import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["main.mjs"],
  outDir: "dist",
  format: ["esm"],
  target: "node22",
  platform: "node",
  bundle: true,
  // electron itself must stay external - it is provided at runtime
  external: ["electron"],
  // inline all workspace packages - Electron must never import TS sources
  noExternal: [/^@dlos\//],
  clean: true,
});
