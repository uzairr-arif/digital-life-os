import { exec } from "node:child_process";
import type { Command } from "commander";
import chalk from "chalk";
import { startServer } from "@dlos/server";
import { fail, ctxFrom, note } from "../ui";

function openBrowser(url: string): void {
  const cmd =
    process.platform === "win32"
      ? `start "" "${url}"`
      : process.platform === "darwin"
        ? `open "${url}"`
        : `xdg-open "${url}"`;
  exec(cmd, () => {
    /* opening the browser is best-effort; the URL is printed regardless */
  });
}

export function registerUiCommand(program: Command): void {
  program
    .command("ui")
    .description("Serve the local dashboard on 127.0.0.1 and open it in a browser")
    .option("--port <n>", "fixed port (default: a free port is chosen)")
    .option("--no-open", "do not open a browser automatically")
    .option("--timeout-ms <n>", "per-check network timeout for scans from the UI", "12000")
    .action(async (opts, cmd) => {
      const { storage, dbPath } = ctxFrom(cmd);
      const port = Number(opts.port);
      if (opts.port !== undefined && (!Number.isInteger(port) || port < 1024 || port > 65535)) {
        return fail("--port must be an integer between 1024 and 65535");
      }
      const timeoutMs = Number(opts.timeoutMs);
      if (!Number.isFinite(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120_000) {
        return fail("--timeout-ms must be between 1000 and 120000");
      }

      const server = await startServer({ storage, port: opts.port ? port : 0, timeoutMs });
      console.log(chalk.bold(`dlos dashboard: ${chalk.underline(server.url)}`));
      console.log(chalk.gray(`database: ${dbPath}`));
      console.log(chalk.gray("bound to 127.0.0.1 only · Ctrl+C to stop"));
      if (opts.open) openBrowser(server.url);
      process.on("SIGINT", () => {
        void server.close().then(() => process.exit(0));
      });
      note("the scan trigger is gated by a per-boot token; nothing else can mutate data");
    });
}
