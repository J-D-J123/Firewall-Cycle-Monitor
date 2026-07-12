"use strict";
/*
 * Electron main process.
 *
 *  - spawns the Python engine (from engine/.venv) and waits for its "ready" line
 *  - opens the UI window
 *  - lives in the system tray: closing the window hides it, only "Quit" exits
 *  - on quit, asks the engine to restore the system proxy, then tears it down
 */
const { app, BrowserWindow, Tray, Menu, nativeImage, shell, ipcMain, Notification } = require("electron");
const { spawn, execFile } = require("child_process");
const path = require("path");
const fs = require("fs");
const readline = require("readline");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const API_PORT = Number(process.env.RCM_API_PORT || 8788);
const PROXY_PORT = Number(process.env.RCM_PROXY_PORT || 8080);
const API_BASE = `http://127.0.0.1:${API_PORT}`;
const WS_URL = `ws://127.0.0.1:${API_PORT}/ws`;

let mainWindow = null;
let tray = null;
let engineProc = null;
let engineReady = false;
let isQuitting = false;

// When Windows auto-starts us at login, the login-item entry passes --hidden so
// we come up minimized to the tray instead of popping a window in the user's face.
const startHidden = process.argv.includes("--hidden");

// ---------------------------------------------------------------------------
// Engine process
// ---------------------------------------------------------------------------
function resolveEnginePython() {
  const venvPy = path.join(PROJECT_ROOT, "engine", ".venv", "Scripts", "python.exe");
  if (fs.existsSync(venvPy)) return { cmd: venvPy, preArgs: [] };
  // Fallbacks if the venv wasn't created yet.
  return { cmd: "py", preArgs: ["-3.12"] };
}

function startEngine() {
  const { cmd, preArgs } = resolveEnginePython();
  const args = [
    ...preArgs,
    path.join(PROJECT_ROOT, "engine", "main.py"),
    "--api-port", String(API_PORT),
    "--proxy-port", String(PROXY_PORT),
  ];
  // Optional safety/testing switch: run the local proxy without changing the
  // Windows system proxy. Set RCM_NO_SYSTEM_PROXY=1 in the environment.
  if (process.env.RCM_NO_SYSTEM_PROXY === "1") args.push("--no-system-proxy");
  // Auto-start (launched via the elevated launcher with --hidden): tell the
  // engine to fail closed - block all outbound until the proxy is intercepting.
  if (startHidden) args.push("--startup-lockdown");
  // Log everything the engine prints to logs/engine.log (the console is hidden).
  const logDir = path.join(PROJECT_ROOT, "logs");
  try { fs.mkdirSync(logDir, { recursive: true }); } catch (_) {}
  let engineLog = null;
  try {
    engineLog = fs.createWriteStream(path.join(logDir, "engine.log"), { flags: "a" });
    engineLog.write(`\n===== launch ${new Date().toISOString()} api=${API_PORT} proxy=${PROXY_PORT} python=${cmd} =====\n`);
  } catch (_) {}
  const logLine = (s) => { try { if (engineLog) engineLog.write(s); } catch (_) {} };

  engineProc = spawn(cmd, args, {
    cwd: PROJECT_ROOT,
    windowsHide: true,
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
  });

  engineProc.on("error", (e) => logLine(`[spawn-error] ${e.message}\n`));

  const rl = readline.createInterface({ input: engineProc.stdout });
  rl.on("line", (line) => {
    logLine(`[out] ${line}\n`);
    let msg = null;
    try { msg = JSON.parse(line); } catch (_) { /* plain log line */ }
    if (msg && msg.event === "ready") {
      engineReady = true;
      console.log("[engine] ready", msg);
      if (mainWindow) mainWindow.webContents.send("engine-ready", msg);
    } else {
      console.log("[engine]", line);
    }
  });
  engineProc.stderr.on("data", (d) => { logLine(`[err] ${d.toString()}`); console.error("[engine:err]", d.toString().trim()); });
  engineProc.on("exit", (code) => {
    logLine(`[exit] code=${code}\n`);
    console.log("[engine] exited", code);
    engineProc = null;
    if (!isQuitting && mainWindow) {
      mainWindow.webContents.send("engine-exited", { code });
    }
  });
}

async function shutdownEngine() {
  try {
    await fetch(`${API_BASE}/shutdown`, { method: "POST" });
  } catch (_) { /* engine may already be gone */ }
  // Give it a moment to restore the system proxy, then hard-stop if needed.
  await new Promise((r) => setTimeout(r, 1200));
  if (engineProc) {
    try { engineProc.kill(); } catch (_) {}
  }
}

// ---------------------------------------------------------------------------
// Window + tray
// ---------------------------------------------------------------------------
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 900,
    minHeight: 560,
    title: "Request Cycle Monitor",
    icon: path.join(__dirname, "assets", "icon-256.png"),
    backgroundColor: "#f4f5f7",
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, "renderer", "index.html"));
  // At a normal launch we show the window once it's painted. When started at
  // login (--hidden) we stay in the tray until the user opens us.
  mainWindow.once("ready-to-show", () => { if (!startHidden) mainWindow.show(); });

  // Closing the window hides to tray instead of quitting.
  mainWindow.on("close", (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
      if (process.platform === "win32" && tray && !mainWindow._notifiedHide) {
        mainWindow._notifiedHide = true;
        tray.displayBalloon &&
          tray.displayBalloon({
            title: "Still running",
            content: "Request Cycle Monitor is minimized to the tray and keeps filtering. Right-click the tray icon to quit.",
          });
      }
    }
  });

  // open external links in the real browser, not inside the app
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });
}

function trayIcon() {
  const img = nativeImage.createFromPath(path.join(__dirname, "assets", "icon.png"));
  return img.isEmpty() ? nativeImage.createEmpty() : img;
}

async function togglePause(pause) {
  try {
    await fetch(`${API_BASE}/control`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: pause ? "pause" : "resume" }),
    });
  } catch (_) {}
  buildTrayMenu();
  if (mainWindow) mainWindow.webContents.send("state-changed");
}

async function currentPaused() {
  try {
    const r = await fetch(`${API_BASE}/state`);
    const s = await r.json();
    return !!(s.settings && s.settings.paused);
  } catch (_) { return false; }
}

async function buildTrayMenu() {
  const paused = await currentPaused();
  const menu = Menu.buildFromTemplate([
    { label: "Show window", click: () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } } },
    { type: "separator" },
    paused
      ? { label: "Resume interception", click: () => togglePause(false) }
      : { label: "Pause interception", click: () => togglePause(true) },
    { type: "separator" },
    {
      label: "Quit (restore proxy)",
      click: async () => {
        isQuitting = true;
        await shutdownEngine();
        app.quit();
      },
    },
  ]);
  if (tray) {
    tray.setContextMenu(menu);
    tray.setToolTip(paused ? "Request Cycle Monitor — paused" : "Request Cycle Monitor");
  }
}

function createTray() {
  tray = new Tray(trayIcon());
  tray.setToolTip("Request Cycle Monitor");
  tray.on("click", () => {
    if (!mainWindow) return;
    if (mainWindow.isVisible()) mainWindow.focus();
    else mainWindow.show();
  });
  buildTrayMenu();
}

// ---------------------------------------------------------------------------
// Launch at login (per-user Run key -> elevated launcher)
// ---------------------------------------------------------------------------
// We register our own value under HKCU\...\CurrentVersion\Run. Writing there is
// per-user and needs no admin. The command runs start.vbs (via wscript) with
// /hidden, and start.vbs does a "runas" ShellExecute - so every sign-in shows a
// UAC prompt and the app comes up elevated (required for the firewall-based
// per-app blocking and the startup kill-switch) and minimized to the tray.
const RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const RUN_VALUE = "Request Cycle Monitor";

function startupCommand() {
  const wscript = path.join(process.env.SystemRoot || "C:\\Windows",
    "System32", "wscript.exe");
  const vbs = path.join(PROJECT_ROOT, "start.vbs");
  return `"${wscript}" "${vbs}" /hidden`;
}

function runReg(regArgs) {
  return new Promise((resolve) => {
    execFile("reg", regArgs, { windowsHide: true }, (err, stdout, stderr) => {
      resolve({ code: err && typeof err.code === "number" ? err.code : (err ? 1 : 0),
                stdout: stdout || "", stderr: stderr || "" });
    });
  });
}

async function readLaunchAtLogin() {
  const r = await runReg(["query", RUN_KEY, "/v", RUN_VALUE]);
  return r.code === 0 && r.stdout.includes(RUN_VALUE);
}

async function writeLaunchAtLogin(enabled) {
  if (enabled) {
    await runReg(["add", RUN_KEY, "/v", RUN_VALUE, "/t", "REG_SZ",
      "/d", startupCommand(), "/f"]);
  } else {
    await runReg(["delete", RUN_KEY, "/v", RUN_VALUE, "/f"]);
  }
  return readLaunchAtLogin();
}

// ---------------------------------------------------------------------------
// IPC exposed to the renderer
// ---------------------------------------------------------------------------
ipcMain.handle("get-launch-at-login", async () => ({ openAtLogin: await readLaunchAtLogin() }));
ipcMain.handle("set-launch-at-login", async (_e, enabled) => ({ openAtLogin: await writeLaunchAtLogin(enabled) }));
ipcMain.handle("get-config", () => ({
  apiBase: API_BASE,
  wsUrl: WS_URL,
  apiPort: API_PORT,
  proxyPort: PROXY_PORT,
  projectRoot: PROJECT_ROOT,
}));
ipcMain.handle("open-path", (_e, p) => shell.openPath(p));
ipcMain.handle("open-external", (_e, url) => shell.openExternal(url));
ipcMain.handle("tray-refresh", () => buildTrayMenu());

// Native OS notification when the new-app guard blocks an unknown app. Clicking
// it brings the window up on the Apps tab so the user can allow/block it.
ipcMain.handle("notify-quarantine", (_e, payload) => {
  try {
    if (!Notification.isSupported()) return { native: false };
    const name = (payload && payload.name) || "An application";
    const reason = (payload && payload.reason) || "it's a new app you haven't allowed yet";
    const n = new Notification({
      title: `Blocked: ${name}`,
      body: `${name} was blocked because ${reason}. Click to choose whether to allow or block it.`,
      icon: path.join(__dirname, "assets", "icon-256.png"),
      silent: false,
    });
    n.on("click", () => {
      if (mainWindow) {
        mainWindow.show();
        mainWindow.focus();
        mainWindow.webContents.send("open-apps");
      }
    });
    n.show();
    return { native: true };
  } catch (e) {
    return { native: false, error: String(e) };
  }
});

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (mainWindow) { mainWindow.show(); mainWindow.focus(); }
  });

  app.whenReady().then(() => {
    // Stable AppUserModelID so Windows attributes toast notifications to us.
    app.setAppUserModelId("Request Cycle Monitor");
    Menu.setApplicationMenu(null); // remove the File/Edit/View/Window/Help bar
    startEngine();
    createWindow();
    createTray();
  });

  // Tray app: do not quit when the window is closed.
  app.on("window-all-closed", (e) => { /* stay alive in tray */ });

  app.on("before-quit", async (e) => {
    if (!isQuitting) {
      isQuitting = true;
      e.preventDefault();
      await shutdownEngine();
      app.quit();
    }
  });
}
