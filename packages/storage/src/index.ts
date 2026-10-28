import { SqliteStorage } from "./storage";

export { SqliteStorage } from "./storage";
export { openDatabase, defaultDbPath } from "./open";

/** Convenience factory: opens (and migrates) a SQLite-backed Storage. */
export function openStorage(dbPath: string): SqliteStorage {
  return new SqliteStorage(dbPath);
}
