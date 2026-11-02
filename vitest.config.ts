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
    include: ["packages/*/tests/**/*.test.ts", "apps/*/tests/**/*.test.ts"],
  },
});
