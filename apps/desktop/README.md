# @dlos/desktop

Electron shell for the dlos local dashboard. The renderer is sandboxed and
context-isolated; the only bridge API is `window.dlosDesktop.serverInfo()`.
All data flows through the same 127.0.0.1 dashboard server the CLI uses
(`@dlos/server`), pointed at the same SQLite database (`~/.dlos/dlos.db`).

```bash
pnpm --filter @dlos/desktop build   # bundle main process (workspace TS -> dist/main.cjs)
pnpm exec electron apps/desktop     # or: pnpm desktop (root script)
```

Packaging installers (electron-builder / forge) is intentionally deferred
until the desktop experience is validated; the shell is fully usable in dev.
