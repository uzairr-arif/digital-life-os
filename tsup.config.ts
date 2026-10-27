import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["apps/cli/src/index.ts"],
  outDir: "apps/cli/dist",
  format: ["esm"],
  target: "node22",
  platform: "node",
  bundle: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  // CJS deps break when bundled into ESM ("Dynamic require of events") —
  // keep them as real runtime imports; they are dependencies of @dlos/cli.
  external: ["commander", "chalk"],
  banner: {
    js: "#!/usr/bin/env node",
  },
});
