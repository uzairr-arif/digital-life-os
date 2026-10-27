import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@dlos/core": `${root}packages/core/src/index.ts`,
      "@dlos/collectors": `${root}packages/collectors/src/index.ts`,
      "@dlos/rules": `${root}packages/rules/src/index.ts`,
      "@dlos/storage": `${root}packages/storage/src/index.ts`,
      "@dlos/reports": `${root}packages/reports/src/index.ts`,
    },
  },
  test: {
    environment: "node",
    // Keep ALL node: builtins (incl. node:sqlite, missing from Vite 5's list) external.
    server: {
      deps: {
        external: [/^node:/],
      },
    },
    include: ["packages/*/tests/**/*.test.ts", "apps/*/tests/**/*.test.ts"],
  },
});
