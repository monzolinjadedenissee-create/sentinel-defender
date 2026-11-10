/* Sentinel console front-end. Vanilla JS, no build step.
   Auth: a server-side login session (cookie). On 401 we bounce to /login. */

const $ = (id) => document.getElementById(id);
let timer = null;
let map = null, markerLayer = null, mapFitted = false, lastPoints = [], lastGeo = null;

const KIND_LABEL = {
  fail: "FAILED", success: "SUCCESS", rate_limited: "RATE-LIMIT",
  suspicious: "SUSPICIOUS", blocked_attempt: "BLOCKED", ip_blocked: "IP BLOCKED",
  account_locked: "ACCT LOCKED",
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function toast(msg, bad) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast show" + (bad ? " bad" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = "toast"), 2600);
}

function toLogin() {
  clearInterval(timer);
  window.location.href = "/admin/login";
}

async function api(path, opts = {}) {
  const res = await fetch("/api/v1/" + path, {
    ...opts,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (res.status === 401) { toLogin(); throw new Error("Unauthorized"); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (!res.ok) throw new Error((data && data.error) || "Request failed");
  return data;
}

function fmtWhen(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch { return iso; }
}

function fmtLeft(secs) {
  if (secs == null) return "permanent";
  if (secs <= 0) return "expiring";
  const m = Math.round(secs / 60);
  if (m < 60) return m + " min";
  const h = Math.floor(m / 60);
  return h + "h " + (m % 60) + "m";
}

/* ---------- Rendering ---------- */

function renderStats(s) {
  $("s_total").textContent = s.total;
  $("s_fails").textContent = s.fails;
  $("s_blocks").textContent = s.blocks;
  $("s_locks").textContent = s.locks;
  $("s_wins").textContent = s.wins;
  $("s_ips").textContent = s.ips;
  $("blockcount").textContent = s.blocks;
  $("lockcount").textContent = s.locks;
}

function renderSpark(buckets) {
  const max = Math.max(1, ...buckets);
  $("spark").innerHTML = buckets
    .map((v) => {
      const h = Math.round((v / max) * 100);
      const hot = v >= max && v > 0 ? 1 : 0;
      return `<div class="bar" data-hot="${hot}" style="height:${Math.max(3, h)}%">${v ? `<span>${v}</span>` : ""}</div>`;
    })
    .join("");
}

function ipLink(ip) {
  if (!ip || ip === "-") return '<span class="ip">—</span>';
  return `<button class="iplink" data-ip="${esc(ip)}" title="Show everything about this IP">${esc(ip)}</button>`;
}

function placeOf(o) {
  return locLabel(o) ? `<span class="loc">📍 ${esc(locLabel(o))}</span>` : "";
}

function renderOffenders(list) {
  const el = $("offenders");
  if (!list.length) { el.innerHTML = '<div class="empty">No hostile traffic yet.</div>'; return; }
  el.innerHTML = list.map((o) => `
    <div class="row">
      <div class="ipline">
        ${ipLink(o.ip)}
        ${placeOf(o)}
        ${o.blocked ? '<span class="pill blocked">blocked</span>' : ""}
      </div>
      <div class="right">
        <span class="pill hot">${o.hits} hits</span>
        <span class="meta">${fmtWhen(o.last)}</span>
      </div>
    </div>`).join("");
}

function locLabel(e) {
  if (e.country && e.country !== "Unknown" && e.country !== "Not resolved" && e.country !== "Private/reserved") {
    const city = e.city && e.city !== "—" ? e.city + ", " : "";
    return city + e.country;
  }
  return "";
}

function deviceLabel(client) {
  try {
    const c = typeof client === "string" ? JSON.parse(client) : client;
    if (!c || typeof c !== "object") return "";
    return [c.platform, c.browser, c.model].filter(Boolean).join(" · ");
  } catch { return ""; }
}

function renderFeed(events) {
  const el = $("feed");
  if (!events.length) { el.innerHTML = '<div class="empty">Waiting for signals…</div>'; return; }
  el.innerHTML = events.map((e) => {
    const label = KIND_LABEL[e.kind] || e.kind.toUpperCase();
    const who = e.account ? ` · ${esc(e.account)}` : "";
    const loc = locLabel(e);
    const dev = deviceLabel(e.client);
    const bits = [`${esc(e.method)} ${esc(e.route)}${who}`];
    if (loc) bits.push("📍 " + esc(loc));
    if (dev) bits.push("🖥 " + esc(dev));
    bits.push(esc(e.note || e.ua || ""));
    const detail = bits.filter(Boolean).join(" — ");
    return `
      <div class="ev">
        <span class="t">${fmtWhen(e.iso)}</span>
        <span class="ip">${ipLink(e.ip)}</span>
        <span class="detail">${detail}</span>
        <span class="kind ${esc(e.kind)}">${esc(label)}</span>
      </div>`;
  }).join("");
}

function renderMap(points, geoInfo) {
  lastPoints = points || [];
  lastGeo = geoInfo || null;
  const note = $("mapnote");
  const located = lastPoints.filter((p) => p.lat != null && p.lon != null);
  $("mapcount").textContent = located.length + " located";
  if (!window.L) { if (note) note.textContent = "Map library did not load."; return; }
  if (!map) {
    map = L.map("map", { worldCopyJump: true, minZoom: 2, maxZoom: 18 }).setView([20, 0], 2);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18, attribution: '&copy; OpenStreetMap contributors',
    }).addTo(map);
    markerLayer = L.layerGroup().addTo(map);
  }
  map.invalidateSize();
  markerLayer.clearLayers();
  if (!located.length) {
    if (note) {
      note.style.display = "grid";
      note.textContent = geoInfo && geoInfo.enabled
        ? "No locatable IPs in the last 24h. Private/local IPs (like 127.0.0.1) can't be placed on a map."
        : "Location database not installed. Run tools/fetch_geo.sh, drop the .mmdb file in the project, and restart to see attackers here.";
    }
    return;
  }
  if (note) note.style.display = "none";
  located.forEach((p) => {
    const icon = L.divIcon({
      className: "pin", iconSize: [26, 26], iconAnchor: [13, 13],
      html: `<div class="pindot ${p.blocked ? "blocked" : ""}">${p.hits}</div>`,
    });
    const where = (p.city && p.city !== "—" ? p.city + ", " : "") + (p.country || "Unknown");
    L.marker([p.lat, p.lon], { icon, title: p.ip }).bindPopup(
      `<span class="pip">${esc(p.ip)}</span><br>${esc(where)}<br>${p.hits} attempt(s)` +
      (p.blocked ? ' · <b style="color:#f06a6a">blocked</b>' : "") +
      `<br><button class="btn" style="margin-top:8px;padding:6px 10px" data-ip="${esc(p.ip)}">Full details</button>`
    ).addTo(markerLayer);
  });
  if (!mapFitted) {
    mapFitted = true;
    try { map.fitBounds(L.latLngBounds(located.map((p) => [p.lat, p.lon])).pad(0.3), { maxZoom: 6 }); } catch {}
  }
}

function renderBlocks(list, now) {
  const el = $("blocks");
  if (!list.length) { el.innerHTML = '<div class="empty">No IPs are blocked.</div>'; return; }
  el.innerHTML = list.map((b) => {
    const left = b.expires == null ? null : b.expires - now;
    return `
    <div class="row">
      <div class="ipline">
        ${ipLink(b.ip)}
        ${placeOf(b)}
        <span class="meta">${esc(b.reason || "")}</span>
      </div>
      <div class="right">
        ${b.hits ? `<span class="pill hot">${b.hits} hits</span>` : ""}
        <span class="pill ${b.manual ? "" : "hot"}">${b.manual ? "manual" : "auto"} · strike ${b.strikes}</span>
        <button class="x" data-ip="${esc(b.ip)}">details</button>
        <span class="meta">${fmtLeft(left)}</span>
        <button class="x" data-unblock="${esc(b.ip)}">unblock</button>
      </div>
    </div>`;
  }).join("");
}

function renderLocks(list, now) {
  const el = $("locks");
  if (!list.length) { el.innerHTML = '<div class="empty">No accounts are locked.</div>'; return; }
  el.innerHTML = list.map((l) => `
    <div class="row">
      <div class="ipline"><span class="ip">${esc(l.account)}</span></div>
      <div class="right">
        <span class="meta">${fmtLeft(l.expires - now)} left</span>
        <button class="x" data-unlock="${esc(l.account)}">release</button>
      </div>
    </div>`).join("");
}

function renderTrusted(list) {
  const el = $("trusted");
  $("trustcount").textContent = list.length;
  if (!list.length) { el.innerHTML = '<div class="empty">Nothing trusted yet.</div>'; return; }
  el.innerHTML = list.map((t) => `
    <div class="row">
      <div class="ipline">
        <span class="ip">${esc(t.cidr)}</span>
        <span class="meta">${esc(t.label || "")}</span>
      </div>
      <div class="right"><button class="x" data-untrust="${esc(t.cidr)}">remove</button></div>
    </div>`).join("");
}

function renderPolicy(rules) {
  const map = [
    ["Storage", rules.storage],
    ["IP fail limit", `${rules.fail_limit} / ${Math.round(rules.fail_window / 60)} min`],
    ["First block", `${Math.round(rules.block_seconds / 60)} min (x2 per strike)`],
    ["Max block", `${Math.round(rules.max_block_seconds / 3600)} h`],
    ["Account lock after", `${rules.account_limit} fails`],
    ["Lock duration", `${Math.round(rules.lock_seconds / 60)} min`],
    ["Retention", `${rules.retention_days} days`],
    ["Webhook alerts", rules.alerts ? "on" : "off"],
  ];
  $("policy").innerHTML = map.map(([k, v]) =>
    `<div class="p"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join("");
  $("storagetag").textContent = rules.storage;

  $("snippet").textContent =
`# After every login attempt, tell Sentinel (never send the password):
curl -X POST "$SENTINEL_URL/api/v1/signal" \\
  -H "X-Sentinel-Signal: $SIGNAL_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"kind":"fail","ip":"203.0.113.7","account":"admin","route":"/login"}'

# Before processing a login, ask whether the IP/account may proceed:
curl -X POST "$SENTINEL_URL/api/v1/gate" \\
  -H "X-Sentinel-Signal: $SIGNAL_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"ip":"203.0.113.7","account":"admin"}'
# -> {"allowed": false, "verdict": "ip_blocked", "retry_after": 840}`;
}

/* ---------- Attacker details window ---------- */

let modalIp = null;

function fmtFull(iso) { try { return new Date(iso).toLocaleString(); } catch { return iso || "—"; } }
function ago(iso) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!isFinite(s)) return "";
  if (s < 60) return Math.max(0, Math.round(s)) + "s ago";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 86400) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " d ago";
}
function parseClient(c) { if (c && typeof c === "object") return c; try { return c ? JSON.parse(c) : {}; } catch { return {}; } }
function tzOffset(tz) {
  try {
    const s = new Date().toLocaleString("en-US", { timeZone: tz, timeZoneName: "shortOffset" }).split("GMT")[1] || "0";
    const [h, m] = s.split(":"); const hh = Number(h || 0);
    return hh + Math.sign(hh || 1) * Number(m || 0) / 60;
  } catch { return null; }
}
function localTime(tz) { try { return new Date().toLocaleTimeString([], { timeZone: tz, hour: "2-digit", minute: "2-digit" }); } catch { return ""; } }
const NETWORK = {
  hosting: '<span class="t-amber">Data centre / VPN / cloud — often a bot or a hidden location</span>',
  isp: "Internet provider (home or mobile)",
};
const dl = (pairs) => pairs.filter(([, v]) => v).map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("") ||
  '<dt></dt><dd class="muted">Nothing recorded</dd>';

function ipCard(i) {
  const status = i.blocked ? '<span class="status blocked">BLOCKED</span>'
    : i.trusted ? '<span class="status trusted">TRUSTED</span>' : '<span class="status watch">WATCHING</span>';
  const place = [i.city, i.region, i.country].filter(Boolean).filter((v, ix, a) => a.indexOf(v) === ix).join(", ");
  const riskColor = i.risk >= 70 ? "var(--red)" : i.risk >= 40 ? "var(--amber)" : "var(--green)";
  const riskWord = i.risk >= 70 ? "High" : i.risk >= 40 ? "Medium" : "Low";
  const c = parseClient((i.devices.find((d) => d.client) || {}).client);

  let tzRow = "";
  if (c.tz) {
    const off = tzOffset(c.tz);
    const odd = i.timezone && i.timezone !== c.tz && tzOffset(i.timezone) !== off;
    tzRow = `${esc(c.tz)} <span class="muted">UTC${off >= 0 ? "+" : ""}${off}</span>` +
      (odd ? ' <span class="t-amber">· differs from the IP location — possible VPN / proxy</span>' : "");
  }

  const location = dl([
    ["Location", i.scope === "private" ? "Private / local network (no location)"
      : place ? esc(place) + (i.country_code ? `<span class="cc">${esc(i.country_code)}</span>` : "")
      : '<span class="muted">Not in the location database</span>'],
    ["Continent", esc(i.continent || "")],
    ["Postal code", esc(i.postal || "")],
    ["Coordinates", i.lat != null ? `${Number(i.lat).toFixed(4)}, ${Number(i.lon).toFixed(4)}` +
      (i.accuracy_km ? ` <span class="muted">± ${i.accuracy_km} km</span>` : "") : ""],
    ["IP time zone", i.timezone ? `${esc(i.timezone)} <span class="muted">local time ${esc(localTime(i.timezone))}</span>` : ""],
  ]);
  const network = dl([
    ["Provider", esc(i.org || "")],
    ["ASN", i.asn ? "AS" + esc(i.asn) : ""],
    ["Network type", NETWORK[i.network] || ""],
    ["IP version", i.version ? "IPv" + i.version : ""],
  ]);
  const activity = dl([
    ["First seen", i.first ? esc(fmtFull(i.first)) : ""],
    ["Last seen", i.last ? `${esc(fmtFull(i.last))} <span class="muted">${ago(i.last)}</span>` : ""],
    ["Speed", i.rate_per_min != null ? `${i.rate_per_min} hostile attempts / min` : ""],
    ["Pages hit", i.routes.map(([r, n]) => `<code>${esc(r)} ×${n}</code>`).join("")],
    ["Locked accounts", i.locked_accounts.map((u) => `<code>${esc(u)}</code>`).join("")],
    ["Block", i.block ? (i.blocked
      ? (i.block.expires == null ? '<span class="t-red">permanent</span>' : `<span class="t-red">ends in ${fmtLeft(i.block.retry)}</span>`)
      : '<span class="muted">expired / lifted</span>') +
      ` · strike ${i.block.strikes} · ${i.block.manual ? "manual" : "auto"}` +
      (i.block.reason ? `<br><span class="muted">${esc(i.block.reason)}</span>` : "") : ""],
  ]);
  const device = dl([
    ["Device time zone", tzRow],
    ["Language", esc(c.language || "")],
    ["Screen", esc(c.screen || "")],
    ["Platform", esc(c.platform || "")],
    ["Browser", esc(c.browser || "")],
    ["Mobile", esc(c.mobile || "")],
  ]);
  const devices = i.devices.map((d) => {
    const label = d.tool ? `<b>${esc(d.tool)}</b> <span class="t-amber">automated</span>`
      : ([d.browser, d.os].filter(Boolean).map(esc).join(" · ") || "Unknown client") +
        (d.type ? ` <span class="muted">${esc(d.type)}</span>` : "");
    return `<div class="dev">${label} <span class="muted">×${d.count}</span>
      <div class="muted" style="font-family:var(--mono);font-size:10.5px;overflow-wrap:anywhere">${esc(d.ua)}</div></div>`;
  }).join("") || '<div class="muted small">No user-agent recorded.</div>';
  const users = i.usernames.length ? i.usernames.map(([u, n]) => `<code>${esc(u)} ×${n}</code>`).join("")
    : '<span class="muted small">None</span>';
  const events = i.events.length ? `<table class="mini"><tbody>${i.events.map((e) => `<tr>
      <td class="mono">${esc(fmtFull(e.iso))}</td>
      <td><span class="kind ${esc(e.kind)}">${esc(KIND_LABEL[e.kind] || e.kind)}</span></td>
      <td>${esc(e.account || "—")}</td>
      <td class="muted">${esc(e.note || e.route || "")}</td></tr>`).join("")}</tbody></table>`
    : '<div class="muted small">No events.</div>';

  const enc = encodeURIComponent(i.ip);
  const external = i.scope === "public" ? `
    <a class="btn ghost" href="https://www.abuseipdb.com/check/${enc}" target="_blank" rel="noopener">AbuseIPDB ↗</a>
    <a class="btn ghost" href="https://ipinfo.io/${enc}" target="_blank" rel="noopener">ipinfo ↗</a>
    <a class="btn ghost" href="https://www.whois.com/whois/${enc}" target="_blank" rel="noopener">WHOIS ↗</a>
    ${i.lat != null ? `<a class="btn ghost" href="https://www.google.com/maps?q=${i.lat},${i.lon}" target="_blank" rel="noopener">Google Maps ↗</a>` : ""}` : "";
  const actions = i.blocked
    ? `<button class="btn danger" data-unblock="${esc(i.ip)}">Unblock</button>`
    : i.trusted
      ? `<button class="btn" data-untrust="${esc(i.ip)}">Remove from trusted</button>`
      : `<input id="mdmin" type="number" min="0" value="60" title="Minutes — 0 = permanent">
         <input id="mdreason" class="reason" placeholder="Reason (optional)">
         <button class="btn primary" data-ipblock="${esc(i.ip)}">Block IP</button>
         <button class="btn" data-iptrust="${esc(i.ip)}">Trust</button>`;

  return `
    <div class="ip-head">
      <div><b id="ipmodaltitle">${esc(i.ip)}</b>
        <div class="sub">${place ? "📍 " + esc(place) : i.scope === "private" ? "Private / local network" : "Location unknown"}${i.org ? " · " + esc(i.org) : ""}</div></div>
      ${status}
    </div>
    <div class="risk"><span class="muted small">Threat level</span>
      <div class="meter"><span style="width:${i.risk}%;background:${riskColor}"></span></div>
      <b style="color:${riskColor}">${riskWord} · ${i.risk}</b></div>
    <div class="kpis">
      <div><span>Attempts</span><strong>${i.attempts}</strong></div>
      <div><span>Failed</span><strong class="t-red">${i.fails}</strong></div>
      <div><span>Tried while blocked</span><strong class="t-amber">${i.blocked_tries}</strong></div>
      <div><span>Successful</span><strong class="t-green">${i.successes}</strong></div>
    </div>
    <div class="ipgrid">
      <div class="ipsec"><h4>Location</h4><dl>${location}</dl></div>
      <div class="ipsec"><h4>Network</h4><dl>${network}</dl></div>
      <div class="ipsec"><h4>Activity</h4><dl>${activity}</dl></div>
      <div class="ipsec"><h4>Device fingerprint</h4><dl>${device}</dl></div>
      <div class="ipsec full"><h4>Usernames tried</h4>${users}</div>
      <div class="ipsec full"><h4>Devices / tools (${i.devices.length})</h4>${devices}</div>
      <div class="ipsec full"><h4>Latest events</h4>${events}</div>
    </div>
    <div class="ip-actions">${actions}${external}</div>
    <div class="ipnote">Location and provider are approximate: an IP points to an internet provider's area, not a person
      or street address. VPNs, proxies and mobile networks can mislead attribution.</div>`;
}

async function loadIp() {
  if (!modalIp) return;
  try { $("ipmodalbody").innerHTML = ipCard(await api("ip/" + encodeURIComponent(modalIp))); }
  catch (e) { $("ipmodalbody").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}
function openIp(ip) {
  modalIp = ip;
  $("ipmodal").hidden = false;
  $("ipmodalbody").innerHTML = '<div class="empty">Loading attacker profile…</div>';
  loadIp();
}
function closeIp() { modalIp = null; $("ipmodal").hidden = true; }

$("ipmodalclose").addEventListener("click", closeIp);
$("ipmodal").addEventListener("click", (e) => { if (e.target.id === "ipmodal") closeIp(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && modalIp) closeIp(); });

/* ---------- Refresh loop ---------- */

async function refresh() {
  try {
    const d = await api("snapshot");
    renderStats(d.stats);
    renderSpark(d.buckets);
    renderOffenders(d.offenders);
    renderFeed(d.events);
    renderBlocks(d.blocks, d.now);
    renderLocks(d.locks, d.now);
    renderTrusted(d.trusted);
    renderPolicy(d.rules);
    renderMap(d.points, d.geo);
  } catch (e) {
    if (e.message !== "Unauthorized") toast(e.message, true);
  }
}

/* ---------- Session ---------- */

async function logout() {
  try { await fetch("/admin/logout", { method: "POST", credentials: "same-origin" }); } catch {}
  toLogin();
}

$("logout").addEventListener("click", logout);
$("refresh").addEventListener("click", refresh);

/* Tabs */
$("tabs").addEventListener("click", (e) => {
  const tab = e.target.closest(".tab");
  if (!tab) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === tab));
  document.querySelectorAll(".panel").forEach((p) =>
    p.classList.toggle("active", p.dataset.view === tab.dataset.tab));
  // Leaflet needs a resize nudge once its panel becomes visible.
  if (tab.dataset.tab === "map") setTimeout(() => renderMap(lastPoints, lastGeo), 60);
});

/* Delegated actions */
document.addEventListener("click", async (e) => {
  const open = e.target.closest("[data-ip]");
  const unblock = e.target.closest("[data-unblock]");
  const unlock = e.target.closest("[data-unlock]");
  const untrust = e.target.closest("[data-untrust]");
  const ipblock = e.target.closest("[data-ipblock]");
  const iptrust = e.target.closest("[data-iptrust]");
  try {
    if (open) { openIp(open.dataset.ip); return; }
    if (unblock) { await api("blocks/" + encodeURIComponent(unblock.dataset.unblock), { method: "DELETE" }); toast("Block lifted"); }
    else if (unlock) { await api("locks/" + encodeURIComponent(unlock.dataset.unlock), { method: "DELETE" }); toast("Account released"); }
    else if (untrust) {
      const v = untrust.dataset.untrust;
      await api("trusted?cidr=" + encodeURIComponent(v.includes("/") ? v : v + (v.includes(":") ? "/128" : "/32")), { method: "DELETE" });
      toast("Removed from trusted");
    }
    else if (ipblock) {
      await api("blocks", { method: "POST", body: JSON.stringify({
        ip: ipblock.dataset.ipblock,
        minutes: Number(($("mdmin") || {}).value || 60),
        reason: (($("mdreason") || {}).value || "").trim() || "Blocked from attacker details" }) });
      toast("IP blocked");
    }
    else if (iptrust) {
      await api("trusted", { method: "POST", body: JSON.stringify({ cidr: iptrust.dataset.iptrust, label: "Trusted from attacker details" }) });
      toast("IP trusted");
    }
    else return;
    refresh();
    loadIp();
  } catch (err) { toast(err.message, true); }
});

/* Forms */
$("blockform").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  try {
    await api("blocks", { method: "POST", body: JSON.stringify({
      ip: f.ip.value.trim(), minutes: Number(f.minutes.value || 60), reason: f.reason.value.trim() }) });
    f.reset(); f.minutes.value = 60; toast("IP blocked"); refresh();
  } catch (err) { toast(err.message, true); }
});

$("trustform").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  try {
    await api("trusted", { method: "POST", body: JSON.stringify({
      cidr: f.cidr.value.trim(), label: f.label.value.trim() }) });
    f.reset(); toast("Range trusted"); refresh();
  } catch (err) { toast(err.message, true); }
});

$("export").addEventListener("click", async () => {
  try {
    const res = await fetch("/api/v1/stream.csv", { credentials: "same-origin" });
    if (res.status === 401) return toLogin();
    if (!res.ok) throw new Error("Export failed");
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url; a.download = "sentinel-events.csv"; a.click();
    URL.revokeObjectURL(url); toast("CSV ready");
  } catch (err) { toast(err.message, true); }
});

$("clear").addEventListener("click", async () => {
  if (!confirm("Delete all recorded events?")) return;
  const all = confirm("Also clear every block and locked account for a fresh start?\n\nOK = wipe them too · Cancel = keep them");
  try { await api("events" + (all ? "?all=1" : ""), { method: "DELETE" }); toast(all ? "Fresh start" : "History cleared"); refresh(); }
  catch (err) { toast(err.message, true); }
});

/* Boot: the page is only served to a logged-in admin, so start the live loop.
   If the session expires, the next poll's 401 bounces us to /login. */
(function boot() {
  refresh();
  timer = setInterval(refresh, 5000);
})();
