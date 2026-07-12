# Request Cycle Monitor & Modifier

A personal Windows privacy tool that lets you **see, edit, and block the network
requests your apps make**. It runs a local decrypting proxy (the same mechanism
as Fiddler / Charles / mitmproxy), attributes each request to the app that made
it, and gives you a UI to inspect traffic, block spyware/telemetry, and rewrite
what you send and receive. When you close the window it keeps running in the
**system tray** (bottom-right notification area).

> This is a defensive tool for **your own machine**. It only inspects traffic on
> this PC. Decrypting HTTPS requires trusting a local certificate — that step is
> explicit, opt-in, and fully reversible.

---

## What it does

- **Monitor** — a live feed of every request/response: time, app, method, host,
  path, status, and whether it was passed / blocked / modified. Click any row to
  see full headers and bodies.
- **Modify** — rules to strip or set headers, find-and-replace in request or
  response bodies, redirect, or delay. Plus **edit & replay** any captured
  request.
- **Block** — curated block lists for Windows/Microsoft telemetry, ad networks,
  social trackers, and third-party app telemetry, plus your own custom hosts and
  rules.
- **Current-app-only focus** — scope monitoring or enforcement to just the app
  you currently have in the foreground.
- **Logs** — a timestamped **session log** every time you launch the monitor,
  plus a system-wide **activity log** recording when apps launch and what they
  connected to.
- **Tray** — closing the window minimizes to the tray and keeps filtering;
  quitting cleanly restores your Windows proxy settings.

---

## Architecture

```
Electron UI  <-- WebSocket (live feed) / REST (control) -->  Python engine
  app/                       127.0.0.1 only                    engine/
  • window + tray                                              • mitmproxy proxy + MITM
  • Live/Rules/Logs/                                           • FastAPI control plane
    Activity/Settings                                          • rule engine + block lists
                                                               • per-app attribution
                                                               • process/network monitors
                                                               • system-proxy + cert mgmt
```

The Electron shell spawns the Python engine, waits for its `ready` signal, and
then connects. All engine endpoints are bound to `127.0.0.1`.

---

## Requirements

- Windows 10/11
- Python 3.12 (the `py -3.12` launcher) — used to build `engine/.venv`
- Node.js (for Electron)

Both are already present if you ran this from the machine it was built on.

## Setup (one time)

Double-click **`setup.cmd`**, or from a terminal:

```
setup.cmd
```

This creates `engine/.venv`, installs the Python dependencies
(`mitmproxy`, `fastapi`, `uvicorn`, `psutil`, `pywin32`), and installs Electron.

## Run

Double-click **`start.vbs`** (recommended — opens only the GUI, no console
window), or `start.cmd` which delegates to it. Both request administrator rights
(needed for per-app firewall blocking); if you decline, the app still runs with
limited blocking.

Tip: right-click `start.vbs` → *Send to* → *Desktop (create shortcut)*, rename it
to "Request Cycle Monitor", and set its icon to `app/assets/icon-256.png` for a
clean one-click launcher.

---

## First run — trust the HTTPS certificate

To read/modify **HTTPS** (not just plain HTTP), Windows must trust the proxy's
local certificate:

1. Launch the app and leave it running for a few seconds (this generates the
   certificate at `%USERPROFILE%\.mitmproxy\`).
2. Go to **Settings → HTTPS certificate → Install & trust**.
3. Accept the Windows security prompt that appears.

The status pill at the top will switch to **certificate trusted**.

**To remove it later:** Settings → *Remove trust* (or run
`certutil -user -delstore Root mitmproxy`).

---

## Using it

- **Settings → Proxy**: the system proxy is **on by default** now, so traffic is
  intercepted from launch. Install & trust the certificate first (below) or HTTPS
  sites will show certificate warnings. Turning it off (or quitting) restores your
  previous Windows proxy settings.
- **Rules & Blocking**: toggle block-list categories, add custom hosts, and
  create rules (block / edit headers / find-replace body / redirect / delay),
  scoped to all apps, a specific `.exe`, or the current foreground app.
- **Settings → Focus**: *Only the app I'm using* limits the tool to the
  foreground app. Choose *Enforce* (rules apply only to that app; feed shows
  everything) or *Monitor* (feed shows only that app).
- **Logs / Activity**: browse past sessions and system activity. *Open logs
  folder* reveals the raw `.jsonl` files under `logs/`.

---

## Where things are stored

```
config/settings.json        your preferences
config/rules.json           your rules
config/proxy_backup.json    saved Windows proxy state (only exists while active)
logs/sessions/*.jsonl       one file per monitor run
logs/activity/YYYY-MM-DD.jsonl   app launches + connections per day
```

---

## Limitations (please read)

- **Proxy-aware traffic only.** It intercepts apps that honor the Windows system
  proxy (browsers and most well-behaved apps). Apps that ignore the proxy, or
  use **certificate pinning**, won't be intercepted. Kernel-level enforcement
  (WinDivert) is a possible future upgrade.
- **Per-app attribution is best-effort.** Very short-lived connections can close
  before we map their source port to a process.
- **Restore safety.** If the engine ever crashes while the system proxy is
  redirected, it restores your original settings automatically on the next
  launch (`config/proxy_backup.json`).

## Running the engine on its own (for debugging)

```
engine\.venv\Scripts\python.exe engine\main.py --api-port 8788 --proxy-port 8080 --no-system-proxy
```

`--no-system-proxy` runs the local proxy without changing your Windows settings.

## Troubleshooting

- **Certificate won't trust** — make sure the app ran once so the CA exists at
  `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer`, then retry Install & trust.
- **No traffic in the feed** — confirm *Route system traffic through the
  monitor* is on (Settings) and the top pill shows `system proxy → monitor`.
- **Port already in use** — set `RCM_API_PORT` / `RCM_PROXY_PORT` environment
  variables before launching to change the ports.
