"use strict";
/*
 * Minimal, safe bridge to the renderer. No Node APIs are exposed - only the
 * engine's local base URL and a couple of shell helpers. The renderer talks to
 * the engine directly over http/ws (the engine is bound to 127.0.0.1 and allows
 * CORS from the app).
 */
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("rcm", {
  getConfig: () => ipcRenderer.invoke("get-config"),
  // Per-user "launch at Windows login" preference (HKCU Run key, no admin).
  getLaunchAtLogin: () => ipcRenderer.invoke("get-launch-at-login"),
  setLaunchAtLogin: (enabled) => ipcRenderer.invoke("set-launch-at-login", enabled),
  openPath: (p) => ipcRenderer.invoke("open-path", p),
  openExternal: (url) => ipcRenderer.invoke("open-external", url),
  refreshTray: () => ipcRenderer.invoke("tray-refresh"),
  // Show a native OS notification for a newly-quarantined app. Resolves with
  // { native: true } if the OS displayed it, so the renderer knows whether it
  // needs to fall back to an in-app card.
  notifyQuarantine: (payload) => ipcRenderer.invoke("notify-quarantine", payload),
  onEngineReady: (cb) => ipcRenderer.on("engine-ready", (_e, msg) => cb(msg)),
  onEngineExited: (cb) => ipcRenderer.on("engine-exited", (_e, msg) => cb(msg)),
  onStateChanged: (cb) => ipcRenderer.on("state-changed", () => cb()),
  // Fired when the user clicks a native quarantine notification.
  onOpenApps: (cb) => ipcRenderer.on("open-apps", () => cb()),
});
