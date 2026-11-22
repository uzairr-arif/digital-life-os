/**
 * The entire Electron-to-renderer bridge. Sandboxed preload: only ipcRenderer
 * and contextBridge are available here by design. Expose as little as possible.
 */
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("dlosDesktop", {
  /** Returns { url, version, desktop } - nothing else crosses the bridge. */
  serverInfo: () => ipcRenderer.invoke("dlos:server-info"),
});
