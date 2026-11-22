// Copies dashboard static assets next to the bundled main so packaged desktop
// builds can serve them (resolvePublicDir finds dist/public).
const { cpSync, existsSync } = require("node:fs");
const { join } = require("node:path");

const src = join(__dirname, "..", "packages", "server", "public");
const dst = join(__dirname, "..", "apps", "desktop", "dist", "public");
if (existsSync(src)) {
  cpSync(src, dst, { recursive: true });
  console.log("public assets copied to apps/desktop/dist/public");
} else {
  console.error("public dir missing:", src);
  process.exit(1);
}
