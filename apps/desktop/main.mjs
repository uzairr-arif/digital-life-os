/**
 * dlos desktop shell.
 *
 * Architecture: the Electron main process starts the SAME local dashboard
 * server the CLI uses (127.0.0.1, per-boot token) and loads it in a window
 * with a sandboxed, context-isolated renderer. The only bridge API exposed
 * to the renderer is `window.dlosDesktop.serverInfo()`. No filesystem, no
 * shell, no Node access. All data flows through the localhost boundary,
 * exactly like the browser flow.
 *
 * ESM on purpose: the bundled output must keep import.meta.url alive for
 * node:sqlite loading and asset resolution. Do not switch to CJS output.
 */
import { app, BrowserWindow, ipcMain } from "electron";
import { join } from "node:path";
import { startServer } from "@dlos/server";
import { defaultDbPath, openStorage } from "@dlos/storage";

/** @type {import('electron').BrowserWindow | null} */
let win = null;
/** @type {import('@dlos/server').ServerHandle | null} */
let server = null;

app.whenReady().then(async () => {
  const storage = openStorage(process.env.DLOS_DB || defaultDbPath());
  server = await startServer({ storage });

  win = new BrowserWindow({
    width: 1280,
    height: 850,
    minWidth: 1024,
    minHeight: 680,
    backgroundColor: "#0A0A0B",
    title: "dlos - digital life os",
    webPreferences: {
      preload: join(import.meta.dirname, "..", "preload.cjs"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webviewTag: false,
    },
  });
  win.removeMenu();
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));

  ipcMain.handle("dlos:server-info", () => ({
    url: server.url,
    version: app.getVersion(),
    desktop: true,
  }));

  await win.loadURL(server.url);
});

app.on("window-all-closed", () => {
  if (server) void server.close();
  app.quit();
});
