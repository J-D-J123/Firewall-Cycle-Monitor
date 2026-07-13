"use strict";
/* Renderer logic. Talks to the engine over http/ws (see preload for the base URL). */

let CFG = null;
let API = "";
const $ = (id) => document.getElementById(id);
const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };

function toast(msg, ms = 2600) {
  const t = $("toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(t._t); t._t = setTimeout(() => (t.hidden = true), ms);
}

async function api(path, opts) {
  const r = await fetch(API + path, opts);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("application/json") ? r.json() : r.text();
}
const post = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
const put = (path, body) => api(path, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const del = (path) => api(path, { method: "DELETE" });

// ===========================================================================
// Tabs
// ===========================================================================
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $("tab-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "apps") loadApps();
    if (tab.dataset.tab === "rules") { loadProfiles(); loadRules(); loadBlocklists(); }
    if (tab.dataset.tab === "logs") loadSessions();
    if (tab.dataset.tab === "activity") loadActivity();
    if (tab.dataset.tab === "settings") syncSettings();
  });
});

// ===========================================================================
// Apps dashboard
// ===========================================================================
let appsFilter = "";
let appsCat = "all";      // all | app | system | unknown
let appsStatus = "all";   // all | new | allowed | blocked
let appsData = null;
// Which category sections / vendor groups the user has collapsed. Kept across
// the periodic re-render so a minimized group stays minimized.
const collapsedGroups = new Set();

const CAT_LABELS = { app: "Applications", system: "System processes", unknown: "Unknown processes" };
const CAT_ORDER = ["app", "system", "unknown"];

async function loadApps() {
  try { appsData = await api("/apps"); } catch (_) { return; }
  renderApps();
}

function isBlockedStatus(a) { return a.effectively_blocked && !a.pending; }
// "Allowed" = anything currently permitted to use the network: not blocked, not
// awaiting a decision, and not shut out by an "only this app" (solo) selection.
function isAllowedStatus(a) { return !a.effectively_blocked; }
function matchesAppFilters(a) {
  if (appsFilter && !a.name.toLowerCase().includes(appsFilter)) return false;
  if (appsCat !== "all" && (a.category || "unknown") !== appsCat) return false;
  if (appsStatus === "new" && !a.pending) return false;
  if (appsStatus === "allowed" && !isAllowedStatus(a)) return false;
  if (appsStatus === "blocked" && !isBlockedStatus(a)) return false;
  return true;
}

function updateAppChipCounts() {
  // counts respect the text filter only, so each facet shows its full scale
  const base = appsData.apps.filter((a) => !appsFilter || a.name.toLowerCase().includes(appsFilter));
  const cat = { all: base.length, app: 0, system: 0, unknown: 0 };
  const st = { all: base.length, new: 0, allowed: 0, blocked: 0 };
  base.forEach((a) => {
    cat[a.category || "unknown"] = (cat[a.category || "unknown"] || 0) + 1;
    if (a.pending) st.new++;
    if (isAllowedStatus(a)) st.allowed++;
    if (isBlockedStatus(a)) st.blocked++;
  });
  document.querySelectorAll("#appsCatFilters .chip").forEach((c) => {
    c.querySelector(".chip-n").textContent = cat[c.dataset.cat] || 0;
  });
  document.querySelectorAll("#appsStatusFilters .chip").forEach((c) => {
    c.querySelector(".chip-n").textContent = st[c.dataset.status] || 0;
  });
}

function renderApps() {
  if (!appsData) return;
  const note = $("appsNote");
  const isAdmin = lastState && lastState.is_admin;
  if (!isAdmin) {
    note.innerHTML = "⚠ <b>Per-app blocking is not fully active.</b> To truly cut off an app (all traffic, including Chrome's), quit and relaunch with <b>start.cmd</b> — it will ask for administrator rights (Windows Firewall needs them). Without admin, “Block” only affects traffic that goes through the proxy.";
  } else if (!appsData.proxy_active) {
    note.innerHTML = "Firewall blocking is active. (The Live feed and header/body rules also need the proxy on — Settings.)";
  } else {
    note.innerHTML = "";
  }
  const solo = appsData.solo_app;
  $("btnUnsolo").hidden = !solo;
  updateAppChipCounts();
  const shown = appsData.apps.filter(matchesAppFilters);
  $("appsBanner").textContent = solo
    ? `Only "${solo}" may use the network — everything else is blocked`
    : `${shown.length} of ${appsData.apps.length} apps shown`;
  const grid = $("appsGrid"); grid.innerHTML = "";
  const groups = { app: [], system: [], unknown: [] };
  shown.forEach((a) => (groups[a.category] || groups.unknown).push(a));
  let any = false;
  CAT_ORDER.forEach((key) => {
    const list = groups[key];
    if (!list.length) return;
    any = true;
    const gkey = "cat:" + key;
    const section = el("div", "apps-section" + (collapsedGroups.has(gkey) ? " collapsed" : ""));
    const head = el("div", "apps-section-head");
    head.innerHTML =
      `<span class="grp-title"><span class="apps-caret">▾</span>${CAT_LABELS[key]}</span>` +
      `<span class="muted small">${list.length}</span>`;
    const body = el("div", "apps-section-body");
    renderCategory(body, list, key);
    head.addEventListener("click", () => toggleGroup(section, gkey));
    section.appendChild(head);
    section.appendChild(body);
    grid.appendChild(section);
  });
  if (!any) grid.appendChild(el("div", "muted small", "No apps match these filters."));
}

// Collapse/expand a category section or vendor group, remembering the choice so
// the next auto-refresh doesn't pop it back open.
function toggleGroup(node, key) {
  const collapsed = node.classList.toggle("collapsed");
  if (collapsed) collapsedGroups.add(key);
  else collapsedGroups.delete(key);
}

// Within a category, collapse a vendor's multiple processes (e.g. Norton's
// several services) under one sub-heading. Single-process vendors and apps with
// no known vendor render as plain cards above the grouped ones.
function renderCategory(section, list, catKey) {
  const byVendor = new Map();
  list.forEach((a) => {
    const label = (a.group || "").trim();
    const key = label ? "v:" + label.toLowerCase() : "_";
    if (!byVendor.has(key)) byVendor.set(key, { label, apps: [] });
    byVendor.get(key).apps.push(a);
  });
  const ungrouped = [];
  const subGroups = [];
  byVendor.forEach((v) => { (v.label && v.apps.length >= 2 ? subGroups : ungrouped).push(v); });
  const flat = [];
  ungrouped.forEach((v) => flat.push(...v.apps));
  if (flat.length) {
    const sg = el("div", "apps-grid");
    flat.forEach((a) => sg.appendChild(appCard(a)));
    section.appendChild(sg);
  }
  subGroups.sort((a, b) => a.label.localeCompare(b.label));
  subGroups.forEach((v) => {
    const gkey = "cat:" + catKey + ":v:" + v.label.toLowerCase();
    const grp = el("div", "apps-vendor" + (collapsedGroups.has(gkey) ? " collapsed" : ""));
    const sub = el("div", "apps-subhead");
    sub.innerHTML =
      `<span class="grp-title"><span class="apps-caret">▾</span>${escapeHtml(v.label)}</span>` +
      `<span class="muted small">${v.apps.length} processes</span>`;
    const sg = el("div", "apps-grid");
    v.apps.forEach((a) => sg.appendChild(appCard(a)));
    sub.addEventListener("click", () => toggleGroup(grp, gkey));
    grp.appendChild(sub);
    grp.appendChild(sg);
    section.appendChild(grp);
  });
}
function appCard(a) {
  const card = el("div", "app-card" + (a.effectively_blocked ? " blocked" : "") + (a.is_solo ? " solo" : ""));
  const initial = (a.name || "?").replace(/\.exe$/i, "").charAt(0) || "?";
  const tags = [];
  if (a.foreground) tags.push('<span class="app-tag fg">foreground</span>');
  if (a.offline) tags.push('<span class="app-tag">not running</span>');
  if (a.pending) tags.push('<span class="app-tag new">new — blocked</span>');
  if (isAllowedStatus(a) && !a.is_solo) tags.push('<span class="app-tag ok">allowed</span>');
  if (a.is_solo) tags.push('<span class="app-tag solo">solo</span>');
  else if (a.policy_blocked) tags.push('<span class="app-tag blk">blocked</span>');
  else if (a.effectively_blocked) tags.push('<span class="app-tag blk">blocked by solo</span>');
  const hosts = (a.top_hosts || []).map((h) => `${h.host} (${h.count})`).concat(a.remotes || []).slice(0, 8);
  card.innerHTML = `
    <div class="app-top">
      <div class="app-avatar"></div>
      <div style="flex:1;min-width:0">
        <div class="app-name">${escapeHtml(a.name)} ${tags.join(" ")}</div>
        <div class="app-exe">${escapeHtml(a.exe || (a.pid ? "pid " + a.pid : "seen via proxy"))}</div>
      </div>
    </div>
    <div class="app-metrics">
      <div><b>${a.established}</b>live conns</div>
      <div><b>${a.requests}</b>requests</div>
      <div><b>${a.blocked_count}</b>blocked</div>
    </div>
    ${hosts.length ? `<div class="app-hosts">${hosts.map(escapeHtml).join("<br>")}</div>` : `<div class="muted small">No destinations captured yet.</div>`}
    <div class="app-domains-hint">Click to block specific domains ›</div>
    <div class="app-actions"></div>`;
  // Click the card body (not the action buttons) to manage which domains this
  // specific app is allowed to reach.
  card.addEventListener("click", (e) => {
    if (e.target.closest(".app-actions")) return;
    openDomainModal(a);
  });
  // real app icon (from its .exe) with a letter fallback
  const avatar = card.querySelector(".app-avatar");
  if (a.exe) {
    const img = document.createElement("img");
    img.className = "app-icon";
    img.alt = "";
    img.src = `${API}/icon?path=${encodeURIComponent(a.exe)}`;
    img.addEventListener("error", () => { avatar.textContent = initial; });
    avatar.appendChild(img);
  } else {
    avatar.textContent = initial;
  }
  const actions = card.querySelector(".app-actions");
  if (a.pending) {
    const allowBtn = el("button", "btn btn-sm btn-primary", "Allow network");
    allowBtn.addEventListener("click", async () => {
      await post("/apps/policy", { action: "allow", name: a.name, exe: a.exe });
      toast("Allowed " + a.name);
      loadApps();
    });
    actions.appendChild(allowBtn);
  }
  const blockBtn = el("button", "btn btn-sm " + (a.policy_blocked ? "btn-primary" : "btn-warn"), a.policy_blocked ? "Allow network" : "Block network");
  blockBtn.addEventListener("click", async () => {
    const res = await post("/apps/policy", { action: a.policy_blocked ? "unblock" : "block", name: a.name, exe: a.exe });
    if (res.firewall && res.firewall.needs_admin) toast("Blocked for proxied traffic only — relaunch as administrator to fully cut off this app.");
    else if (res.firewall && res.firewall.ok) toast("Firewall block applied — all of " + a.name + "'s traffic is cut off.");
    loadApps();
  });
  actions.appendChild(blockBtn);
  const soloBtn = el("button", "btn btn-sm " + (a.is_solo ? "btn-ghost" : ""), a.is_solo ? "Un-solo" : "Only this app");
  soloBtn.addEventListener("click", async () => { await post("/apps/policy", { action: a.is_solo ? "unsolo" : "solo", name: a.name }); loadApps(); });
  actions.appendChild(soloBtn);
  return card;
}
// ---------------------------------------------------------------------------
// Per-app domain blocking (click an app card)
// ---------------------------------------------------------------------------
// Blocking a domain "for an app" is just a rule scoped to that exe, so this
// reuses the rules engine — no new backend needed.
let domainApp = null;

function blockRulePayload(appName, host) {
  return {
    name: `Block ${host} for ${appName}`,
    enabled: true,
    match: { host, app_scope: { type: "exe", value: appName } },
    action: { type: "block", params: { status: 403 } },
  };
}
// A rule that blocks `host` specifically for `appName` (exact host, exe scope).
function findAppDomainRule(rules, appName, host) {
  const an = appName.toLowerCase(), hn = host.toLowerCase();
  return rules.find((r) =>
    r.action && r.action.type === "block" &&
    r.match && r.match.app_scope && r.match.app_scope.type === "exe" &&
    String(r.match.app_scope.value || "").toLowerCase() === an &&
    String(r.match.host || "").toLowerCase() === hn);
}
function cleanHost(v) {
  return String(v || "").trim().toLowerCase()
    .replace(/^[a-z]+:\/\//, "")   // strip scheme
    .replace(/\/.*$/, "")           // strip path
    .replace(/:\d+$/, "");          // strip port
}

async function openDomainModal(a) {
  domainApp = a;
  $("domainModalTitle").textContent = "Domains — " + a.name;
  $("domainAddInput").value = "";
  $("domainModal").hidden = false;
  syncProtoToggles();
  await renderDomainList();
}
function closeDomainModal() { $("domainModal").hidden = true; domainApp = null; }

// Per-app firewall (non-web) blocks — reflected from the persisted settings.
function syncProtoToggles() {
  const a = domainApp;
  if (!a) return;
  const protos = (lastState && lastState.settings && lastState.settings.app_proto_blocks) || [];
  const an = a.name.toLowerCase(), ae = (a.exe || "").toLowerCase();
  const has = (p) => protos.some((b) => b.proto === p &&
    (String(b.name || "").toLowerCase() === an || (ae && String(b.exe || "").toLowerCase() === ae)));
  $("protoIcmp").checked = has("icmp");
  $("protoQuic").checked = has("quic");
}
async function setProto(proto, block) {
  const a = domainApp;
  if (!a) return;
  const res = await post("/apps/proto", { name: a.name, exe: a.exe, proto, block });
  const fw = res.firewall || {};
  if (fw.needs_admin) toast("Saved — relaunch as administrator (start.cmd) to enforce.");
  else toast(`${block ? "Blocked" : "Unblocked"} ${proto === "icmp" ? "ping" : "QUIC"} for ${a.name}`);
  await pollState();
  syncProtoToggles();
}

async function renderDomainList() {
  const a = domainApp;
  if (!a) return;
  // Full domain usage for this app (busiest first), plus the current rules so we
  // know which are already blocked. Fall back to the app card's capped host list
  // if the engine predates the /apps/hosts endpoint.
  const rules = await api("/rules");
  let usage = null;
  try { usage = await api("/apps/hosts?name=" + encodeURIComponent(a.name)); } catch (_) {}
  const usageHosts = (usage && Array.isArray(usage.hosts))
    ? usage.hosts
    : (a.top_hosts || []);
  const countByHost = new Map(usageHosts.map((h) => [String(h.host).toLowerCase(), h.count]));

  const an = a.name.toLowerCase();
  const blockedByHost = new Map();
  rules.forEach((r) => {
    if (r.action && r.action.type === "block" && r.match && r.match.app_scope &&
        r.match.app_scope.type === "exe" &&
        String(r.match.app_scope.value || "").toLowerCase() === an && r.match.host) {
      blockedByHost.set(String(r.match.host).toLowerCase(), r);
    }
  });

  // Ordered list: every domain the app has used (busiest first), then any
  // blocked-by-rule domain it isn't currently talking to.
  const order = [];
  const seen = new Set();
  usageHosts.forEach((h) => {
    const host = h.host;
    if (host && !seen.has(host.toLowerCase())) { seen.add(host.toLowerCase()); order.push(host); }
  });
  blockedByHost.forEach((r) => {
    const host = r.match.host;
    if (host && !seen.has(host.toLowerCase())) { seen.add(host.toLowerCase()); order.push(host); }
  });

  const list = $("domainList");
  list.innerHTML = "";
  $("domainCount").textContent = order.length
    ? `${order.length} domain${order.length > 1 ? "s" : ""} seen — busiest first`
    : "";
  if (!order.length) {
    list.appendChild(el("div", "muted small", "No domains seen for this app yet. Type one above to block it."));
    return;
  }
  order.forEach((host) => {
    const rule = blockedByHost.get(host.toLowerCase());
    const blocked = !!rule;
    const count = countByHost.get(host.toLowerCase());
    const row = el("div", "domain-row" + (blocked ? " blocked" : ""));
    const info = el("div", "domain-info");
    info.appendChild(el("span", "domain-host", host));
    info.appendChild(el("span", "domain-count",
      count != null ? `${count.toLocaleString()} request${count === 1 ? "" : "s"}` : "not seen recently"));
    row.appendChild(info);
    if (blocked) row.appendChild(el("span", "domain-badge", "blocked"));
    const btn = el("button", "btn btn-sm " + (blocked ? "" : "btn-warn"), blocked ? "Unblock" : "Block");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      if (blocked) await del("/rules/" + rule.id);
      else await post("/rules", blockRulePayload(a.name, host));
      await renderDomainList();
      loadApps();
    });
    row.appendChild(btn);
    list.appendChild(row);
  });
}

async function addDomainBlock() {
  const a = domainApp;
  if (!a) return;
  const host = cleanHost($("domainAddInput").value);
  if (!host) return;
  const rules = await api("/rules");
  if (findAppDomainRule(rules, a.name, host)) {
    toast(host + " is already blocked for " + a.name);
  } else {
    await post("/rules", blockRulePayload(a.name, host));
    toast(`Blocked ${host} for ${a.name}`);
  }
  $("domainAddInput").value = "";
  await renderDomainList();
  loadApps();
}

$("domainModalClose").addEventListener("click", closeDomainModal);
$("domainModalDone").addEventListener("click", closeDomainModal);
$("domainModal").addEventListener("click", (e) => { if (e.target.id === "domainModal") closeDomainModal(); });
$("domainAddBtn").addEventListener("click", addDomainBlock);
$("domainAddInput").addEventListener("keydown", (e) => { if (e.key === "Enter") addDomainBlock(); });
$("protoIcmp").addEventListener("change", (e) => setProto("icmp", e.target.checked));
$("protoQuic").addEventListener("change", (e) => setProto("quic", e.target.checked));

$("appsFilter").addEventListener("input", (e) => { appsFilter = e.target.value.trim().toLowerCase(); renderApps(); });
$("btnRefreshApps").addEventListener("click", loadApps);
$("btnUnsolo").addEventListener("click", async () => { await post("/apps/policy", { action: "unsolo" }); loadApps(); });
document.querySelectorAll("#appsCatFilters .chip").forEach((c) => c.addEventListener("click", () => {
  appsCat = c.dataset.cat;
  document.querySelectorAll("#appsCatFilters .chip").forEach((x) => x.classList.toggle("active", x === c));
  renderApps();
}));
document.querySelectorAll("#appsStatusFilters .chip").forEach((c) => c.addEventListener("click", () => {
  appsStatus = c.dataset.status;
  document.querySelectorAll("#appsStatusFilters .chip").forEach((x) => x.classList.toggle("active", x === c));
  renderApps();
}));

// ===========================================================================
// Live feed
// ===========================================================================
const flows = new Map();     // flow_id -> { req, resp, row }
const MAX_ROWS = 1500;
let liveFilter = "";

function methodColor(m) { return m; }
function statusClass(s) { if (!s) return ""; return "status-" + String(s)[0]; }

function matchesFilter(f) {
  if (!liveFilter) return true;
  const hay = `${f.req.host}${f.req.path} ${f.req.app?.name || ""} ${f.req.method}`.toLowerCase();
  return hay.includes(liveFilter);
}

function makeRow(f) {
  const tr = el("tr");
  tr.dataset.flow = f.req.flow_id;
  const time = new Date().toLocaleTimeString();
  tr.innerHTML = `
    <td class="mono">${time}</td>
    <td title="${f.req.app?.exe || ""}">${escapeHtml(f.req.app?.name || "—")}</td>
    <td class="mono">${escapeHtml(f.req.method)}</td>
    <td><span class="host">${escapeHtml(f.req.host)}</span><span class="path">${escapeHtml(f.req.path)}</span></td>
    <td class="status-cell mono"></td>
    <td class="action-cell"></td>`;
  setActionCell(tr, f);
  tr.addEventListener("click", () => showDetail(f, tr));
  return tr;
}

function setActionCell(tr, f) {
  const cell = tr.querySelector(".action-cell");
  const a = f.req.action || "pass";
  cell.innerHTML = `<span class="badge ${a}">${a}</span>` +
    (f.req.matched && f.req.matched.length ? ` <span class="muted small" title="${escapeHtml(f.req.matched.join(', '))}">•</span>` : "");
  tr.classList.toggle("row-blocked", !!f.req.blocked);
  tr.classList.toggle("row-modified", !f.req.blocked && !!(f.req.modified || (f.resp && f.resp.modified)));
  // A blocked request never hits the server, so show the status we return (403)
  // right away so it's obvious in the feed which ones were stopped.
  if (f.req.blocked && !f.resp) {
    const sc = tr.querySelector(".status-cell");
    const code = f.req.status || 403;
    sc.textContent = code;
    sc.className = "status-cell mono " + statusClass(code);
  }
}

function onEvent(ev) {
  if (ev.type === "request") {
    let f = flows.get(ev.flow_id);
    if (!f) { f = { req: ev, resp: null, row: null }; flows.set(ev.flow_id, f); }
    else { f.req = ev; }
    if (!f.row) {
      f.row = makeRow(f);
      const body = $("liveBody");
      body.appendChild(f.row);
      if (!matchesFilter(f)) f.row.style.display = "none";
      while (body.children.length > MAX_ROWS) {
        const first = body.firstElementChild;
        flows.delete(first.dataset.flow);
        first.remove();
      }
      if ($("autoScroll").checked) f.row.scrollIntoView({ block: "nearest" });
    } else setActionCell(f.row, f);
  } else if (ev.type === "response") {
    const f = flows.get(ev.flow_id);
    if (f) {
      f.resp = ev;
      if (f.row) {
        const sc = f.row.querySelector(".status-cell");
        sc.textContent = ev.status || "";
        sc.className = "status-cell mono " + statusClass(ev.status);
        setActionCell(f.row, f);
      }
    }
  }
  updateCounters();
}

let counters = { req: 0, blocked: 0, modified: 0 };
function updateCounters() {
  counters = { req: 0, blocked: 0, modified: 0 };
  flows.forEach((f) => {
    counters.req++;
    if (f.req.blocked) counters.blocked++;
    else if (f.req.modified || (f.resp && f.resp.modified)) counters.modified++;
  });
  $("liveCounters").textContent = `${counters.req} requests · ${counters.blocked} blocked · ${counters.modified} modified`;
}

$("liveFilter").addEventListener("input", (e) => {
  liveFilter = e.target.value.trim().toLowerCase();
  flows.forEach((f) => { if (f.row) f.row.style.display = matchesFilter(f) ? "" : "none"; });
});
$("btnClearLive").addEventListener("click", () => {
  flows.clear(); $("liveBody").innerHTML = ""; updateCounters(); closeDetail();
});

// -- detail panel + replay --------------------------------------------------
let detailFlow = null;
function headersToText(list) { return (list || []).map(([k, v]) => `${k}: ${v}`).join("\n"); }

function showDetail(f, tr) {
  detailFlow = f;
  document.querySelectorAll("#liveBody tr").forEach((r) => r.classList.remove("selected"));
  tr.classList.add("selected");
  $("detail").hidden = false;
  $("detailTitle").textContent = `${f.req.method} ${f.req.host}`;
  const r = f.req, rs = f.resp;
  let html = "";
  html += `<h4>Request</h4><div class="kv"><b>${escapeHtml(r.method)}</b> ${escapeHtml(r.url)}\napp: <b>${escapeHtml(r.app?.name || "—")}</b> (pid ${r.app?.pid ?? "?"})\naction: <b>${r.action}</b>${r.reason ? " — " + escapeHtml(r.reason) : ""}</div>`;
  html += `<h4>Request headers</h4><pre class="body">${escapeHtml(headersToText(r.req_headers))}</pre>`;
  if (r.req_body && r.req_body.size) html += `<h4>Request body (${r.req_body.size} bytes${r.req_body.truncated ? ", truncated" : ""})</h4><pre class="body">${escapeHtml(r.req_body.text)}</pre>`;
  if (rs) {
    html += `<h4>Response</h4><div class="kv">status: <b>${rs.status}</b> ${escapeHtml(rs.reason || "")}\nlatency: ${rs.latency_ms ?? "?"} ms · ${escapeHtml(rs.content_type || "")}</div>`;
    html += `<h4>Response headers</h4><pre class="body">${escapeHtml(headersToText(rs.resp_headers))}</pre>`;
    if (rs.resp_body && rs.resp_body.size) html += `<h4>Response body (${rs.resp_body.size} bytes${rs.resp_body.truncated ? ", truncated" : ""})</h4><pre class="body">${escapeHtml(rs.resp_body.text)}</pre>`;
  } else html += `<div class="muted small" style="margin-top:10px">Waiting for response…</div>`;
  $("detailBody").innerHTML = html;
}
function closeDetail() { $("detail").hidden = true; detailFlow = null; }
$("detailClose").addEventListener("click", closeDetail);

$("btnReplay").addEventListener("click", () => {
  if (!detailFlow) return;
  const r = detailFlow.req;
  const headers = {}; (r.req_headers || []).forEach(([k, v]) => (headers[k] = v));
  $("detailBody").innerHTML = `
    <h4>Edit &amp; replay</h4>
    <label class="field-label">Method</label><input class="input" id="rpMethod" value="${escapeAttr(r.method)}"/>
    <label class="field-label">URL</label><input class="input" id="rpUrl" value="${escapeAttr(r.url)}"/>
    <label class="field-label">Headers (Name: value per line)</label><textarea class="input" id="rpHeaders" rows="6">${escapeHtml(headersToText(r.req_headers))}</textarea>
    <label class="field-label">Body</label><textarea class="input" id="rpBody" rows="4">${escapeHtml(r.req_body?.text || "")}</textarea>
    <button class="btn btn-primary" id="rpSend" style="margin-top:10px">Send through proxy</button>
    <div class="muted small" id="rpResult" style="margin-top:8px"></div>`;
  $("rpSend").addEventListener("click", async () => {
    const hdrs = {};
    $("rpHeaders").value.split("\n").forEach((ln) => {
      const i = ln.indexOf(":"); if (i > 0) hdrs[ln.slice(0, i).trim()] = ln.slice(i + 1).trim();
    });
    $("rpResult").textContent = "Sending…";
    try {
      const res = await post("/replay", { method: $("rpMethod").value, url: $("rpUrl").value, headers: hdrs, body: $("rpBody").value });
      $("rpResult").textContent = res.ok ? `→ ${res.status}` : `error: ${res.error}`;
    } catch (e) { $("rpResult").textContent = "error: " + e.message; }
  });
});

// ===========================================================================
// State polling -> status pills + settings controls
// ===========================================================================
let lastState = null;
async function pollState() {
  try {
    const s = await api("/state");
    lastState = s;
    renderPills(s);
    renderQuarantine(s.pending_apps);
    if ($("tab-settings").classList.contains("active")) applyStateToSettings(s);
    if ($("tab-activity").classList.contains("active")) applyActivity(s);
  } catch (_) { renderOffline(); }
}
function pill(id, cls, txt) { const p = $(id); p.className = "pill " + cls; p.textContent = txt; }

// Baseline for the live per-second rates (delta between /state polls).
let lastRate = null;

function renderPills(s) {
  const sp = s.system_proxy || {};
  const cert = s.cert || {};
  const st = s.settings || {};
  const stats = s.stats || {};

  // Proxy status — one pill that reflects whether you're actually protected:
  // the local proxy must be up, Windows must be routing to it, and the cert must
  // be trusted (otherwise HTTPS can't be inspected).
  if (!s.proxy_active) {
    pill("pill-proxy", "bad", "proxy off");
  } else if (st.paused) {
    pill("pill-proxy", "warn", "paused");
  } else if (!sp.pointing_at_us) {
    pill("pill-proxy", "warn", "proxy up · not routing");
  } else if (cert.available && cert.trusted === false) {
    pill("pill-proxy", "warn", "proxy on · cert untrusted");
  } else {
    pill("pill-proxy", "ok", `proxy on :${st.proxy_port}`);
  }

  // Live per-second throughput, averaged over the interval since the last poll:
  // the accent pill is what got through (accepted), the red one is what's being
  // blocked right now.
  const now = performance.now();
  const reqTotal = stats.requests || 0;
  const blkTotal = stats.blocked || 0;
  let allowedRate = 0, blockedRate = 0;
  if (lastRate && now > lastRate.t) {
    const dt = (now - lastRate.t) / 1000;
    const dReq = reqTotal - lastRate.req;
    const dBlk = blkTotal - lastRate.blocked;
    if (dt > 0 && dReq >= 0 && dBlk >= 0) {
      allowedRate = Math.max(0, dReq - dBlk) / dt;
      blockedRate = dBlk / dt;
    }
  }
  lastRate = { req: reqTotal, blocked: blkTotal, t: now };
  pill("pill-rate", "accent", `${Math.round(allowedRate)} req/s`);
  const br = Math.round(blockedRate);
  pill("pill-blocked", br > 0 ? "bad" : "", `${br} blocked/s`);

  // New apps awaiting a decision — only shown when there are any.
  const pend = (s.pending_apps || []).length;
  const pp = $("pill-pending");
  if (pend > 0) { pp.hidden = false; pill("pill-pending", "warn", `${pend} new app${pend > 1 ? "s" : ""} waiting`); }
  else pp.hidden = true;

  // Focus scope — only shown when narrowed to the current app.
  const fp = $("pill-focus");
  if (st.current_app_only) {
    fp.hidden = false;
    const fg = s.foreground && s.foreground.name ? s.foreground.name : "…";
    pill("pill-focus", "warn", `focus: ${st.focus_mode} · ${fg}`);
  } else { fp.hidden = true; }

  const paused = st.paused;
  $("btnPause").textContent = paused ? "Resume" : "Pause";
  $("btnPause").className = "btn " + (paused ? "btn-primary" : "btn-warn");
}
function renderOffline() {
  lastRate = null;
  pill("pill-proxy", "bad", "engine offline");
  pill("pill-rate", "", "— req/s");
  pill("pill-blocked", "", "— blocked/s");
  $("pill-pending").hidden = true;
  $("pill-focus").hidden = true;
}

$("btnPause").addEventListener("click", async () => {
  const paused = lastState && lastState.settings.paused;
  await post("/control", { action: paused ? "resume" : "pause" });
  await pollState(); window.rcm.refreshTray();
});

// ===========================================================================
// Rules
// ===========================================================================
async function loadRules() {
  const rules = await api("/rules");
  const list = $("rulesList"); list.innerHTML = "";
  if (!rules.length) { list.appendChild(el("div", "muted small", "No rules yet. Add one to block or modify requests.")); return; }
  rules.forEach((rule) => {
    const item = el("div", "rule-item" + (rule.enabled ? "" : " disabled"));
    const main = el("div", "rule-main");
    main.appendChild(el("div", "rule-name", rule.name));
    main.appendChild(el("div", "rule-desc", describeRule(rule)));
    const toggle = document.createElement("label"); toggle.className = "switch";
    toggle.innerHTML = `<input type="checkbox" ${rule.enabled ? "checked" : ""}/><span></span>`;
    toggle.querySelector("input").addEventListener("change", async (e) => {
      await put("/rules/" + rule.id, { enabled: e.target.checked }); loadRules();
    });
    const edit = el("button", "btn btn-ghost btn-sm", "Edit");
    edit.addEventListener("click", () => openRuleModal(rule));
    const rm = el("button", "btn btn-ghost btn-sm", "Delete");
    rm.addEventListener("click", async () => { await del("/rules/" + rule.id); loadRules(); });
    item.append(toggle, main, edit, rm);
    list.appendChild(item);
  });
}
function describeRule(r) {
  const m = r.match || {}, a = r.action || {};
  const scope = m.app_scope?.type === "exe" ? m.app_scope.value : (m.app_scope?.type === "current" ? "current app" : "all apps");
  let act = a.type;
  if (a.type === "block") act = `block (${a.params?.status || 403})`;
  else if (a.type === "modify_headers") act = `edit ${a.params?.target || "request"} headers`;
  else if (a.type === "modify_body") act = `replace in ${a.params?.target || "request"} body`;
  else if (a.type === "redirect") act = `redirect → ${a.params?.url || ""}`;
  else if (a.type === "delay") act = `delay ${a.params?.ms || 0}ms`;
  return `${m.host || "*"}${m.method ? " · " + m.method : ""} · ${scope} → ${act}`;
}

// -- protection profiles ----------------------------------------------------
async function loadProfiles() {
  const data = await api("/profiles");
  const grid = $("profileGrid"); grid.innerHTML = "";
  const currentLabel = { off: "Off", balanced: "Balanced", strict: "Strict", lockdown: "Lockdown", custom: "Custom" }[data.current] || data.current;
  $("profilePill").textContent = "Active: " + currentLabel;
  $("profilePill").className = "pill " + (data.current === "off" || data.current === "custom" ? "" : "ok");
  data.profiles.forEach((p) => {
    const card = el("button", "profile-card" + (p.key === data.current ? " active" : ""));
    card.innerHTML = `<div class="p-title">${escapeHtml(p.label)}</div><div class="p-desc">${escapeHtml(p.description)}</div>`;
    card.addEventListener("click", async () => {
      await post("/profiles/apply", { name: p.key });
      loadProfiles(); loadBlocklists();
      toast("Applied: " + p.label);
    });
    grid.appendChild(card);
  });
}

// -- rule modal -------------------------------------------------------------
function openRuleModal(rule) {
  $("ruleModal").hidden = false;
  $("ruleModalTitle").textContent = rule ? "Edit rule" : "Add rule";
  $("ruleId").value = rule?.id || "";
  $("ruleName").value = rule?.name || "";
  $("ruleEnabled").checked = rule ? rule.enabled : true;
  const m = rule?.match || {}, a = rule?.action || {};
  $("ruleHost").value = m.host || "";
  $("ruleMethod").value = m.method || "";
  $("ruleUrl").value = m.url_pattern || "";
  const scope = m.app_scope?.type || "all";
  $("ruleScope").value = scope; $("ruleExe").value = m.app_scope?.value || "";
  $("ruleExeWrap").hidden = scope !== "exe";
  $("ruleAction").value = a.type || "block";
  const p = a.params || {};
  $("pStatus").value = p.status || 403;
  $("hTarget").value = p.target || "request";
  $("hSet").value = p.set ? Object.entries(p.set).map(([k, v]) => `${k}: ${v}`).join("\n") : "";
  $("hRemove").value = (p.remove || []).join("\n");
  $("bTarget").value = p.target || "request";
  $("bFind").value = p.find || ""; $("bReplace").value = p.replace || ""; $("bRegex").checked = !!p.regex;
  $("rUrl").value = p.url || "";
  $("dMs").value = p.ms || 500;
  showActionParams();
}
function closeRuleModal() { $("ruleModal").hidden = true; }
$("ruleModalClose").addEventListener("click", closeRuleModal);
$("ruleCancel").addEventListener("click", closeRuleModal);
$("btnAddRule").addEventListener("click", () => openRuleModal(null));
$("ruleScope").addEventListener("change", (e) => $("ruleExeWrap").hidden = e.target.value !== "exe");
$("ruleAction").addEventListener("change", showActionParams);
function showActionParams() {
  const v = $("ruleAction").value;
  $("paramsBlock").hidden = v !== "block";
  $("paramsHeaders").hidden = v !== "modify_headers";
  $("paramsBody").hidden = v !== "modify_body";
  $("paramsRedirect").hidden = v !== "redirect";
  $("paramsDelay").hidden = v !== "delay";
}
$("ruleSave").addEventListener("click", async () => {
  const scope = $("ruleScope").value;
  const match = {
    host: $("ruleHost").value.trim() || "*",
    method: $("ruleMethod").value,
    url_pattern: $("ruleUrl").value.trim(),
    app_scope: scope === "exe" ? { type: "exe", value: $("ruleExe").value.trim() } : { type: scope },
  };
  const type = $("ruleAction").value;
  let params = {};
  if (type === "block") params = { status: Number($("pStatus").value) || 403 };
  else if (type === "modify_headers") params = { target: $("hTarget").value, set: parseKV($("hSet").value), remove: lines($("hRemove").value) };
  else if (type === "modify_body") params = { target: $("bTarget").value, find: $("bFind").value, replace: $("bReplace").value, regex: $("bRegex").checked };
  else if (type === "redirect") params = { url: $("rUrl").value.trim() };
  else if (type === "delay") params = { ms: Number($("dMs").value) || 0 };
  const payload = { name: $("ruleName").value.trim() || "Untitled rule", enabled: $("ruleEnabled").checked, match, action: { type, params } };
  const id = $("ruleId").value;
  if (id) await put("/rules/" + id, payload); else await post("/rules", payload);
  closeRuleModal(); loadRules(); toast("Rule saved");
});
function parseKV(text) { const o = {}; text.split("\n").forEach((ln) => { const i = ln.indexOf(":"); if (i > 0) o[ln.slice(0, i).trim()] = ln.slice(i + 1).trim(); }); return o; }
function lines(text) { return text.split("\n").map((s) => s.trim()).filter(Boolean); }

// -- block lists ------------------------------------------------------------
async function loadBlocklists() {
  const cats = await api("/blocklists");
  const wrap = $("blocklists"); wrap.innerHTML = "";
  cats.filter((c) => c.key !== "custom").forEach((c) => {
    const row = el("label", "check"); row.style.justifyContent = "space-between"; row.style.margin = "6px 0";
    row.innerHTML = `<span><input type="checkbox" data-cat="${c.key}" ${c.enabled ? "checked" : ""}/> ${escapeHtml(c.label)}</span><span class="muted small">${c.count}</span>`;
    wrap.appendChild(row);
  });
  const custom = cats.find((c) => c.key === "custom");
  $("customHosts").value = (custom?.hosts || []).join("\n");
}
$("btnSaveBlock").addEventListener("click", async () => {
  const enabled = Array.from(document.querySelectorAll("#blocklists input[data-cat]:checked")).map((i) => i.dataset.cat);
  await post("/blocklists", { enabled_categories: enabled, custom_hosts: lines($("customHosts").value) });
  toast("Block lists saved");
});

// ===========================================================================
// Logs
// ===========================================================================
async function loadSessions() {
  const sessions = await api("/logs/sessions");
  const list = $("sessionList"); list.innerHTML = "";
  if (!sessions.length) { list.appendChild(el("div", "muted small", "No sessions yet.")); return; }
  sessions.forEach((s, idx) => {
    const item = el("div", "list-item" + (idx === 0 ? " active" : ""));
    item.innerHTML = `<div><b>${escapeHtml(s.name.replace("session-", "").replace(".jsonl", ""))}</b></div><div class="muted small">${(s.size / 1024).toFixed(1)} KB</div>`;
    item.addEventListener("click", () => { document.querySelectorAll("#sessionList .list-item").forEach((i) => i.classList.remove("active")); item.classList.add("active"); loadSession(s.name); });
    list.appendChild(item);
  });
  loadSession(sessions[0].name);
}
async function loadSession(name) {
  $("sessionTitle").textContent = name;
  const events = await api("/logs/sessions/" + encodeURIComponent(name));
  const body = $("sessionBody"); body.innerHTML = "";
  events.filter((e) => e.type === "request" || e.type === "response").slice(-800).forEach((e) => {
    const tr = el("tr");
    const t = e.ts ? new Date(e.ts).toLocaleTimeString() : "";
    tr.innerHTML = `<td class="mono">${t}</td><td class="mono">${e.type[0].toUpperCase()}</td>
      <td><span class="host">${escapeHtml(e.host || "")}</span><span class="path">${escapeHtml(e.path || "")}</span></td>
      <td>${escapeHtml(e.app?.name || "")}</td><td class="mono ${statusClass(e.status)}">${e.status || (e.blocked ? "blocked" : "")}</td>`;
    if (e.blocked) tr.classList.add("row-blocked");
    body.appendChild(tr);
  });
}
$("btnRefreshSessions").addEventListener("click", loadSessions);

// ===========================================================================
// Activity
// ===========================================================================
async function loadActivity(date) {
  // Fill the summary (stats + top processes) at the top of the tab right away.
  if (lastState) applyActivity(lastState);
  const data = await api("/logs/activity" + (date ? "?date=" + encodeURIComponent(date) : ""));
  const sel = $("activityDay");
  if (!sel.dataset.filled || !date) {
    sel.innerHTML = ""; (data.days || []).forEach((d) => { const o = el("option", null, d); o.value = d; sel.appendChild(o); });
    if (data.date) sel.value = data.date;
    sel.dataset.filled = "1";
  }
  const body = $("activityBody"); body.innerHTML = "";
  (data.entries || []).slice(-1000).reverse().forEach((e) => {
    const tr = el("tr");
    const t = e.ts ? new Date(e.ts).toLocaleTimeString() : "";
    let details = "";
    if (e.type === "app_launch" || e.type === "app_exit") details = e.exe || "";
    else if (e.type === "connection") details = `→ ${e.remote_ip}:${e.remote_port}`;
    tr.innerHTML = `<td class="mono">${t}</td><td>${escapeHtml(e.type)}</td><td>${escapeHtml(e.name || "")}</td><td class="mono muted">${escapeHtml(details)}</td>`;
    body.appendChild(tr);
  });
}
$("activityDay").addEventListener("change", (e) => loadActivity(e.target.value));

// ===========================================================================
// Settings
// ===========================================================================
function applyStateToSettings(s) {
  const sp = s.system_proxy || {};
  // Toggle reflects the saved preference (persists across restarts); the line
  // below shows the actual live registry state.
  if (document.activeElement !== $("tglSystemProxy")) $("tglSystemProxy").checked = !!s.settings.proxy_enabled;
  const actual = sp.available ? (sp.pointing_at_us ? `on — ${sp.server}` : (sp.enabled ? `other proxy: ${sp.server}` : "off")) : "n/a";
  $("proxyServerLine").textContent = `Preference: ${s.settings.proxy_enabled ? "on" : "off"} · actual: ${actual}`;
  if (document.activeElement !== $("tglCurrentApp")) $("tglCurrentApp").checked = !!s.settings.current_app_only;
  $("focusMode").value = s.settings.focus_mode;
  if (document.activeElement !== $("tglGuard")) $("tglGuard").checked = !!s.settings.guard_new_apps;
  const pend = (s.pending_apps || []).length;
  const allowedN = (s.settings.allowed_apps || []).length;
  $("guardLine").textContent = s.settings.guard_new_apps
    ? `On · ${allowedN} allowed · ${pend} awaiting your decision`
    : "Off — new apps are not blocked";
  const fg = s.foreground && s.foreground.name ? `${s.foreground.name}` : "no window focused";
  $("focusLine").textContent = s.settings.current_app_only ? `Active — foreground: ${fg}` : "Off — all apps monitored";
  const c = s.cert || {};
  $("certLine").innerHTML = c.available
    ? `CA present: <b>${c.exists ? "yes" : "no"}</b> · trusted by Windows: <b>${c.trusted ? "yes" : "no"}</b>`
    : "Certificate management is Windows-only.";
  // Firewall toggle (needs admin to actually enforce)
  const admin = !!s.is_admin;
  if (document.activeElement !== $("tglStrict")) $("tglStrict").checked = !!s.settings.strict_mode;
  $("strictLine").textContent = s.settings.strict_mode
    ? (admin ? "On — only monitored traffic allowed out" : "On — needs admin to enforce") : "Off";
}

function applyActivity(s) {
  const st = s.stats || {};
  const requests = st.requests || 0;
  const blocked = st.blocked || 0;
  const allowed = Math.max(0, requests - blocked);
  $("statRequests").textContent = requests.toLocaleString();
  $("statAllowed").textContent = allowed.toLocaleString();
  $("statBlocked").textContent = blocked.toLocaleString();
  const wrap = $("topApps"); wrap.innerHTML = "";
  const top = s.top_apps || [];
  if (!top.length) { wrap.appendChild(el("div", "muted small", "No traffic yet.")); return; }
  const max = Math.max(...top.map((t) => t.requests), 1);
  top.forEach((t) => {
    const row = el("div", "top-app");
    const pct = Math.max(2, Math.round((t.requests / max) * 100));
    row.innerHTML =
      `<span class="ta-name" title="${escapeAttr(t.name)}">${escapeHtml(t.name)}</span>` +
      `<span class="ta-bar"><span style="width:${pct}%"></span></span>` +
      `<span class="ta-n">${t.requests.toLocaleString()}${t.blocked ? ` · <b class="bad">${t.blocked.toLocaleString()}</b> blocked` : ""}</span>`;
    wrap.appendChild(row);
  });
}
async function syncSettings() {
  if (lastState) applyStateToSettings(lastState);
  if (CFG) $("logPathLine").textContent = CFG.projectRoot + "\\logs";
}
$("tglSystemProxy").addEventListener("change", async (e) => {
  const res = await post("/control", { action: e.target.checked ? "proxy_on" : "proxy_off" });
  const sp = res.system_proxy || {};
  if (sp.ok === false) toast("Proxy change failed: " + (sp.error || ""));
  await pollState();
});
$("tglCurrentApp").addEventListener("change", async (e) => {
  await post("/control", { action: "set_current_app_only", value: e.target.checked });
  await pollState();
});
$("focusMode").addEventListener("change", async (e) => {
  await post("/control", { action: "set_focus_mode", value: e.target.value });
  await pollState();
});
$("tglGuard").addEventListener("change", async (e) => {
  await post("/control", { action: "set_guard_new_apps", value: e.target.checked });
  await pollState();
});
$("tglStrict").addEventListener("change", async (e) => {
  const r = await post("/control", { action: "set_strict_mode", value: e.target.checked });
  if (r && r.is_admin === false) toast("Saved — relaunch as administrator (start.cmd) to enforce strict mode.");
  else if (e.target.checked) toast("Strict mode on — only traffic through the monitor is allowed out. Quit the app to restore.");
  await pollState();
});
async function blockProgram() {
  const name = $("blockProgramInput").value.trim();
  if (!name) return;
  const res = await post("/apps/policy", { action: "block", name });
  const msg = $("blockProgramMsg");
  const fw = res.firewall || {};
  if (fw.ok === false && fw.error) msg.textContent = "Couldn't block: " + fw.error;
  else if (fw.needs_admin) msg.textContent = `Saved “${name}”, but relaunch as administrator to actually cut it off.`;
  else msg.textContent = `Blocked ${name} — see it in the Apps tab to un-block.`;
  $("blockProgramInput").value = "";
  loadApps();
}
$("blockProgramBtn").addEventListener("click", blockProgram);
$("blockProgramInput").addEventListener("keydown", (e) => { if (e.key === "Enter") blockProgram(); });

// Launch at Windows login. This lives in the OS (per-user Run key) rather than
// the engine's state, so we read/write it through the Electron bridge directly.
function paintStartup(on) {
  if (document.activeElement !== $("tglStartup")) $("tglStartup").checked = on;
  $("startupLine").textContent = on
    ? "On — elevated at sign-in (UAC each time); blocks all traffic until the proxy is up"
    : "Off — start it yourself";
}
async function refreshStartup() {
  try {
    const r = await window.rcm.getLaunchAtLogin();
    paintStartup(!!(r && r.openAtLogin));
  } catch (_) { $("startupLine").textContent = "Unavailable on this platform"; }
}
$("tglStartup").addEventListener("change", async (e) => {
  try {
    const r = await window.rcm.setLaunchAtLogin(e.target.checked);
    const on = !!(r && r.openAtLogin);
    paintStartup(on);
    toast(on ? "Will launch elevated at sign-in (asks for admin each time)" : "Won't launch at startup anymore");
  } catch (_) {
    toast("Couldn't change the startup setting");
    refreshStartup();
  }
});
$("btnInstallCert").addEventListener("click", async () => {
  $("certMsg").textContent = "Requesting install… (accept the Windows security prompt if it appears)";
  const res = await post("/cert/install");
  $("certMsg").textContent = res.ok ? "Certificate installed & trusted." : ("Failed: " + (res.error || res.detail || ""));
  await pollState();
});
$("btnUninstallCert").addEventListener("click", async () => {
  const res = await post("/cert/uninstall");
  $("certMsg").textContent = res.ok ? "Certificate trust removed." : ("Failed: " + (res.error || res.detail || ""));
  await pollState();
});
$("btnOpenLogs").addEventListener("click", () => { if (CFG) window.rcm.openPath(CFG.projectRoot + "\\logs"); });

// The session-log viewer no longer has its own top-nav tab; it's reached from
// Settings and returns there. showPanel drives the panels directly.
function showPanel(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
  const panel = $("tab-" + name);
  if (panel) panel.classList.add("active");
}
$("btnViewLogs").addEventListener("click", () => { showPanel("logs"); loadSessions(); });
$("btnLogsBack").addEventListener("click", () => { showPanel("settings"); syncSettings(); });
$("btnViewActivity").addEventListener("click", () => {
  const sec = document.getElementById("systemActivity");
  if (sec) sec.scrollIntoView({ behavior: "smooth", block: "start" });
});

// ===========================================================================
// New-app guard — corner notifications for apps blocked on first connection
// ===========================================================================
const guardCards = new Map();     // name(lower) -> card element
const guardDismissed = new Set(); // names dismissed without a decision

function buildGuardCard(a) {
  const name = a.name || "unknown";
  const card = el("div", "guard-card");
  card.innerHTML = `
    <div class="guard-head">
      <span class="guard-title">New application blocked</span>
      <button class="guard-x" title="Decide later — it stays blocked">✕</button>
    </div>
    <div class="guard-name"></div>
    <div class="guard-exe muted small"></div>
    <div class="guard-msg"></div>
    <div class="guard-actions">
      <button class="btn btn-sm btn-primary guard-allow">Allow</button>
      <button class="btn btn-sm btn-warn guard-block">Block</button>
    </div>`;
  card.querySelector(".guard-name").textContent = name;
  const reason = a.reason || "it's a new app you haven't allowed yet";
  card.querySelector(".guard-msg").textContent =
    `Blocked because ${reason}. Choose what to do — it stays blocked until you decide.`;
  const exeEl = card.querySelector(".guard-exe");
  if (a.exe) exeEl.textContent = a.exe; else exeEl.remove();
  card.querySelector(".guard-x").addEventListener("click", () => dismissGuard(name));
  card.querySelector(".guard-allow").addEventListener("click", () => decideApp(a, "allow"));
  card.querySelector(".guard-block").addEventListener("click", () => decideApp(a, "block"));
  return card;
}

function addGuardCard(a) {
  const key = (a.name || "").toLowerCase();
  if (!key || guardDismissed.has(key) || guardCards.has(key)) return;
  const card = buildGuardCard(a);
  guardCards.set(key, card);
  $("guardStack").appendChild(card);
}
function removeGuardCard(key) {
  const card = guardCards.get(key);
  if (card) { card.remove(); guardCards.delete(key); }
}

// Surface a quarantined app as a native OS notification the first time we see
// it. Only if the OS can't show notifications do we fall back to an in-app card.
const notifiedApps = new Set();
async function surfaceQuarantine(a) {
  const key = (a.name || "").toLowerCase();
  if (!key || notifiedApps.has(key)) return;
  notifiedApps.add(key);
  let native = false;
  try {
    const r = await window.rcm.notifyQuarantine({ name: a.name, exe: a.exe || "", reason: a.reason || "" });
    native = !!(r && r.native);
  } catch (_) {}
  if (!native) { guardDismissed.delete(key); addGuardCard(a); }
}

// live push from the engine the moment an app is quarantined
function onQuarantine(ev) { surfaceQuarantine(ev); }

// reconcile with the engine's current pending list (from /state)
function renderQuarantine(list) {
  const present = new Set();
  (list || []).forEach((a) => {
    const key = (a.name || "").toLowerCase();
    if (!key) return;
    present.add(key);
    surfaceQuarantine(a);
  });
  // an app that's no longer pending: reset notify state and drop any fallback card
  notifiedApps.forEach((key) => { if (!present.has(key)) notifiedApps.delete(key); });
  guardCards.forEach((_card, key) => { if (!present.has(key)) removeGuardCard(key); });
}

// jump to the Apps tab, filtered to apps awaiting a decision
function openAppsNew() {
  showPanel("apps");
  appsStatus = "new";
  document.querySelectorAll("#appsStatusFilters .chip").forEach((x) => x.classList.toggle("active", x.dataset.status === "new"));
  loadApps();
}

function dismissGuard(name) {
  const key = (name || "").toLowerCase();
  guardDismissed.add(key);
  removeGuardCard(key);
}

async function decideApp(a, action) {
  const key = (a.name || "").toLowerCase();
  guardDismissed.add(key);   // suppress re-add while the decision propagates
  notifiedApps.delete(key);  // allow a fresh notification if it's ever re-quarantined
  removeGuardCard(key);
  try {
    const res = await post("/apps/policy", { action, name: a.name, exe: a.exe || "" });
    if (action === "block" && res.firewall && res.firewall.needs_admin)
      toast(`Blocked ${a.name} for proxied traffic — relaunch as administrator to fully cut it off.`);
    else
      toast(action === "allow" ? `Allowed ${a.name}` : `Blocked ${a.name}`);
  } catch (_) { toast("Could not update — is the engine running?"); }
  await pollState();
  if ($("tab-apps").classList.contains("active")) loadApps();
}

// ===========================================================================
// WebSocket
// ===========================================================================
function connectWS() {
  const ws = new WebSocket(CFG.wsUrl);
  ws.onmessage = (msg) => {
    try {
      const ev = JSON.parse(msg.data);
      if (ev.type === "request" || ev.type === "response") onEvent(ev);
      else if (ev.type === "app_quarantined") onQuarantine(ev);
    } catch (_) {}
  };
  ws.onclose = () => setTimeout(connectWS, 2000);
  ws.onerror = () => ws.close();
}

// ===========================================================================
// helpers
// ===========================================================================
function escapeHtml(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function escapeAttr(s) { return escapeHtml(s).replace(/"/g, "&quot;"); }

// ===========================================================================
// boot
// ===========================================================================
(async function init() {
  CFG = await window.rcm.getConfig();
  API = CFG.apiBase;
  window.rcm.onEngineExited(() => renderOffline());
  window.rcm.onOpenApps(() => openAppsNew());
  connectWS();
  await pollState();
  await refreshStartup();
  await loadApps();
  setInterval(pollState, 2000);
  // keep the Apps dashboard fresh while it's the visible tab
  setInterval(() => { if ($("tab-apps").classList.contains("active")) loadApps(); }, 3000);
})();
