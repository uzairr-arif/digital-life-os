import { Command } from "commander";
import chalk from "chalk";
import { TOOL_VERSION } from "@dlos/reports";
import { defaultDbPath } from "@dlos/storage";
import { registerAssetCommands } from "./commands/asset";
import { registerScanCommand } from "./commands/scan";
import { registerFindingsCommands } from "./commands/findings";
import { registerHistoryCommand } from "./commands/history";
import { registerReportCommand } from "./commands/report";

const program = new Command();

program
  .name("dlos")
  .description(
    "Digital Life OS — a local-first, evidence-driven personal security companion.\n\n" +
      "Know what you own, understand what is exposed, fix what matters, and verify the fix.",
  )
  .version(TOOL_VERSION)
  .option("--db <path>", "path to the local SQLite database", defaultDbPath());

registerAssetCommands(program);
registerScanCommand(program);
registerFindingsCommands(program);
registerHistoryCommand(program);
registerReportCommand(program);

program
  .parseAsync(process.argv)
  .catch((err: unknown) => {
    console.error(`${chalk.red("error:")} ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  });
