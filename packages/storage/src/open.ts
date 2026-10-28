import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { homedir } from "node:os";
import { createRequire } from "node:module";
import type { DatabaseSync } from "node:sqlite";
import { migrate } from "./migrations";

// node:sqlite is loaded via createRequire: Vite 5's builtin-module list predates
// node:sqlite, so bundler-based import resolution (vitest) fails to resolve it.
const requireNode = createRequire(import.meta.url);
const sqlite = requireNode("node:sqlite") as typeof import("node:sqlite");

export function defaultDbPath(): string {
  return resolve(homedir(), ".dlos", "dlos.db");
}

/** Opens (creating if needed) a Digital Life OS SQLite database with migrations applied. */
export function openDatabase(dbPath: string): DatabaseSync {
  if (dbPath !== ":memory:") {
    mkdirSync(dirname(dbPath), { recursive: true });
  }
  const db = new sqlite.DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = ON;");
  migrate(db);
  return db;
}
