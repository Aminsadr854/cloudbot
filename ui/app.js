/**
 * Cloudbot Hosting Console - Modern Frontend Controller
 * Enterprise-grade multi-cloud hosting dashboard
 */

// Application State
const state = {
  token: localStorage.getItem("cloudbot_token") || sessionStorage.getItem("cloudbot_token") || "",
  authenticated: false,
  accounts: [],
  accountBilling: {}, // account_id -> { status, info, identity, latency_ms, lastChecked }
  proxyProviders: [],
  activeAccountFilter: "all",
  accountSearchQuery: "",
  servers: [],
  floatingIps: [],
  primaryIps: [],
  sshKeys: [],
  dnsZones: [],
  watchdog: null,
  tunnels: [],
  activeTab: "tab-overview",
  searchQuery: "",
  deploySelectedProvider: "hetzner",
  providerSelectedAccount: { hetzner: null, vultr: null, linode: null },
  providerAccountSubTab: { hetzner: "instances", vultr: "instances", linode: "instances" },
  regionsCache: {},
  plansCache: {},
  imagesCache: {},
  providerIpFilter: "all",
  selectedServers: new Map(),
  selectedIps: new Map(),
  ipsAccountFilter: "all",
  selectedServerModalFips: new Map(),
  accountErrors: {},
  liveAccountFailures: {},
  recoveryStatus: {},
  syncSnapshot: null
};

let syncManager = null;
let authInvalidated = false;
const proxyRecoveryInFlight = new Map();

function isServerRunning(status) {
  if (!status) return true;
  const s = String(status).toLowerCase();
  if (s.includes("stop") || s.includes("suspend") || s.includes("halt") || s.includes("off") || s.includes("shut") || s.includes("error")) {
    return false;
  }
  return s.includes("run") || s.includes("active") || s.includes("ok") || s.includes("online");
}

// Provider Metadata
const PROVIDERS = {
  hetzner: { name: "Hetzner Cloud", logo: "/ui/assets/hetzner.svg", badgeClass: "badge-hetzner", color: "#ef4444" },
  vultr: { name: "Vultr", logo: "/ui/assets/vultr.svg", badgeClass: "badge-vultr", color: "#0ea5e9" },
  linode: { name: "Linode / Akamai", logo: "/ui/assets/linode.svg", badgeClass: "badge-linode", color: "#10b981" }
};

// UI Initialization on DOM ready
document.addEventListener("DOMContentLoaded", async () => {
  initNavigation();
  initSearch();
  initModals();
  initForms();
  initAuth();
  initSyncManager();

  const authed = await checkSessionAuth();
  if (authed) {
    closeModal("modal-auth-login");
    loadAll();
  } else {
    openModal("modal-auth-login");
    initTelegramWidget();
  }
});

// ==================== AUTHENTICATION ====================
async function checkSessionAuth() {
  try {
    const headers = {};
    if (state.token) {
      headers["Authorization"] = `Bearer ${state.token}`;
    }
    const res = await fetch("/v1/auth/me", { headers });
    if (res.ok) {
      const data = await res.json();
      if (data.authenticated) {
        state.authenticated = true;
        authInvalidated = false;
        const userLabel = document.getElementById("auth-user-label");
        if (userLabel && data.bot_username) {
          userLabel.textContent = `@${data.bot_username}`;
        }
        return true;
      }
    }
  } catch (err) {}
  return false;
}

async function initTelegramWidget() {
  try {
    const res = await fetch("/v1/auth/me");
    const data = await res.json();
    const botUser = data.bot_username || "vpnmanagerkiabot";
    const tgLink = document.getElementById("btn-tg-magic-link");
    if (tgLink) {
      tgLink.href = `https://t.me/${botUser}?start=login`;
    }
    const container = document.getElementById("telegram-widget-wrapper");
    if (container && !container.hasChildNodes()) {
      const script = document.createElement("script");
      script.async = true;
      script.src = "https://telegram.org/js/telegram-widget.js?22";
      script.setAttribute("data-telegram-login", botUser);
      script.setAttribute("data-size", "large");
      script.setAttribute("data-onauth", "onTelegramAuth(user)");
      script.setAttribute("data-request-access", "write");
      container.appendChild(script);
    }
  } catch (e) {}
}

window.onTelegramAuth = async function(user) {
  try {
    showToast("Authenticating via Telegram...", "info");
    const res = await fetch("/v1/auth/telegram", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(user)
    });
    const data = await res.json();
    if (res.ok && data.token) {
      state.token = data.token;
      state.authenticated = true;
      authInvalidated = false;
      localStorage.setItem("cloudbot_token", data.token);
      closeModal("modal-auth-login");
      showToast("Telegram authentication successful!", "success");
      loadAll();
    } else {
      showToast(data.error || "Telegram authentication failed", "error");
    }
  } catch (err) {
    showToast("Failed to connect to control server", "error");
  }
};

function initAuth() {
  const switchBtn = document.getElementById("btn-auth-switch");
  const authForm = document.getElementById("form-auth-token");
  const tokenInput = document.getElementById("auth-token-input");
  const rememberCheckbox = document.getElementById("auth-remember-token");

  if (state.token) {
    tokenInput.value = state.token;
  }

  switchBtn.addEventListener("click", () => {
    openModal("modal-auth-login");
    initTelegramWidget();
  });

  authForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const token = tokenInput.value.trim();
    if (!token) return;

    const btn = document.getElementById("btn-submit-auth");
    await runWithButtonLoading(btn, async () => {
      try {
        const res = await fetch("/v1/operations", {
          headers: { "Authorization": `Bearer ${token}` }
        });

        if (!res.ok) {
          throw new Error("Invalid access token (HTTP " + res.status + ")");
        }

        state.token = token;
        state.authenticated = true;
        authInvalidated = false;
        if (rememberCheckbox.checked) {
          localStorage.setItem("cloudbot_token", token);
          sessionStorage.removeItem("cloudbot_token");
        } else {
          sessionStorage.setItem("cloudbot_token", token);
          localStorage.removeItem("cloudbot_token");
        }

        closeModal("modal-auth-login");
        showToast("Authenticated successfully", "success");
        loadAll();
      } catch (err) {
        showToast(err.message, "error");
      }
    }, "Authenticating...");
  });
}

// ==================== API CLIENT ====================
const apiClient = window.CloudbotApiClient.create({
  getToken: () => state.token,
  onUnauthorized: () => {
    if (authInvalidated) return;
    authInvalidated = true;
    state.token = "";
    state.authenticated = false;
    localStorage.removeItem("cloudbot_token");
    sessionStorage.removeItem("cloudbot_token");
    openModal("modal-auth-login");
    initTelegramWidget();
  }
});

async function api(operation, args = {}, options = {}) {
  return apiClient.request(operation, args, options);
}

// ==================== REGION HELPERS ====================
const REGION_MAP = {
  "DE": { name: "Germany", flag: "🇩🇪" },
  "NL": { name: "Netherlands", flag: "🇳🇱" },
  "US": { name: "United States", flag: "🇺🇸" },
  "GB": { name: "United Kingdom", flag: "🇬🇧" },
  "UK": { name: "United Kingdom", flag: "🇬🇧" },
  "SE": { name: "Sweden", flag: "🇸🇪" },
  "BR": { name: "Brazil", flag: "🇧🇷" },
  "SK": { name: "Slovakia", flag: "🇸🇰" },
  "FR": { name: "France", flag: "🇫🇷" },
  "SG": { name: "Singapore", flag: "🇸🇬" },
  "AE": { name: "United Arab Emirates (UAE)", flag: "🇦🇪" },
  "UAE": { name: "United Arab Emirates (UAE)", flag: "🇦🇪" },
  "FI": { name: "Finland", flag: "🇫🇮" },
  "PL": { name: "Poland", flag: "🇵🇱" },
  "ES": { name: "Spain", flag: "🇪🇸" },
  "IT": { name: "Italy", flag: "🇮🇹" },
  "JP": { name: "Japan", flag: "🇯🇵" },
  "AU": { name: "Australia", flag: "🇦🇺" },
  "CA": { name: "Canada", flag: "🇨🇦" },
  "KR": { name: "South Korea", flag: "🇰🇷" },
  "ID": { name: "Indonesia", flag: "🇮🇩" },
  "MY": { name: "Malaysia", flag: "🇲🇾" }
};

const COUNTRY_ALIASES = {
  "UAE": "AE",
  "ARE": "AE",
  "EMIRATES": "AE",
  "UK": "GB",
  "GBR": "GB",
  "USA": "US",
  "DEU": "DE",
  "NLD": "NL",
  "BRA": "BR",
  "SVK": "SK",
  "FRA": "FR",
  "SGP": "SG",
  "FIN": "FI",
  "POL": "PL",
  "ESP": "ES",
  "ITA": "IT",
  "JPN": "JP",
  "AUS": "AU",
  "CAN": "CA",
  "KOR": "KR",
  "IDN": "ID",
  "MYS": "MY",
  "IRN": "IR",
  "TUR": "TR",
  "RUS": "RU"
};

function normalizeCountryCode(val) {
  if (!val || typeof val !== "string") return "";
  const upper = val.trim().toUpperCase();
  return COUNTRY_ALIASES[upper] || upper;
}

function getCountryFlag(code) {
  if (!code || typeof code !== "string") return "🌐";
  const clean = normalizeCountryCode(code);
  if (clean.length !== 2) return "🌐";
  try {
    return String.fromCodePoint(...[...clean].map(c => 127397 + c.charCodeAt(0)));
  } catch (e) {
    return "🌐";
  }
}

function formatRegion(code) {
  if (!code) return { code: "", name: "Not Specified", flag: "🌐" };
  const upper = code.trim().toUpperCase();
  const iso = normalizeCountryCode(upper);
  const flag = getCountryFlag(iso);
  const info = REGION_MAP[iso] || REGION_MAP[upper] || { name: iso === "AE" ? "United Arab Emirates (UAE)" : iso, flag };
  return { code: iso, name: info.name, flag: flag || info.flag };
}

function updateEditRegionPreview(code) {
  const reg = formatRegion(code);
  const flagEl = document.getElementById("edit-region-flag-preview");
  const nameEl = document.getElementById("edit-region-name-preview");
  if (flagEl) flagEl.textContent = reg.flag;
  if (nameEl) nameEl.textContent = reg.name || "Custom Region";
}

function setEditRegionCode(code) {
  const input = document.getElementById("edit-region-select");
  if (input) {
    input.value = code;
    updateEditRegionPreview(code);
  }
}

function updatePoolCountryPreview(code) {
  const reg = formatRegion(code);
  const flagEl = document.getElementById("pool-assign-flag-preview");
  const nameEl = document.getElementById("pool-assign-name-preview");
  if (flagEl) flagEl.textContent = reg.flag;
  if (nameEl) nameEl.textContent = reg.name || "Target pool country";
}

function setPoolAssignCountry(code) {
  const input = document.getElementById("pool-assign-country");
  if (input) {
    input.value = code;
    updatePoolCountryPreview(code);
  }
}

function updateCustomProxyPreview(code) {
  const reg = formatRegion(code);
  const flagEl = document.getElementById("custom-proxy-flag-preview");
  const nameEl = document.getElementById("custom-proxy-name-preview");
  if (flagEl) flagEl.textContent = reg.flag;
  if (nameEl) nameEl.textContent = reg.name || "Custom region";
}

function setCustomProxyRegion(code) {
  const input = document.getElementById("custom-proxy-region");
  if (input) {
    input.value = code;
    updateCustomProxyPreview(code);
  }
}

function setAddAccRegion(code) {
  const input = document.getElementById("acc-region");
  if (input) {
    input.value = code;
    const flagEl = document.getElementById("add-acc-flag-preview");
    if (flagEl) flagEl.textContent = getCountryFlag(code);
    updateAddAccProxyRegionHint(code);
    const poolRadio = document.querySelector('input[name="add-acc-proxy-type"][value="pool"]');
    if (poolRadio && poolRadio.checked) {
      checkAddAccProxyAvailability();
    }
  }
}

function updateAddAccProxyRegionHint(code) {
  const input = document.getElementById("acc-region");
  const regCode = (code || input?.value || "").trim().toUpperCase() || "—";
  const badge = document.getElementById("add-acc-proxy-pool-region-badge");
  if (badge) {
    badge.textContent = `${getCountryFlag(regCode)} ${regCode}`;
  }
}

function populateAddAccProxyProviders() {
  const sel = document.getElementById("add-acc-proxy-provider-select");
  if (!sel) return;
  const providers = (state.proxyProviders || []).filter(p => p.enabled);
  let html = `<option value="auto">⚡ Auto (Best provider matching account region)</option>`;
  for (const p of providers) {
    const total = p.active_sessions || p.total_sessions || 0;
    html += `<option value="${p.id}">${escapeHtml(p.label)} (${total} sessions)</option>`;
  }
  if (providers.length === 0) {
    html = `<option value="" disabled>No active rotating proxy providers configured</option>`;
  }
  sel.innerHTML = html;
}

function switchAddAccountProxyMode(mode) {
  const poolPanel = document.getElementById("add-acc-proxy-pool-panel");
  const customPanel = document.getElementById("add-acc-proxy-custom-panel");
  if (poolPanel) poolPanel.classList.toggle("hidden", mode !== "pool");
  if (customPanel) customPanel.classList.toggle("hidden", mode !== "custom");
  if (mode === "pool") {
    populateAddAccProxyProviders();
    updateAddAccProxyRegionHint();
    checkAddAccProxyAvailability();
  }
}

async function checkAddAccProxyAvailability() {
  const regionInput = document.getElementById("acc-region");
  const region = (regionInput?.value || "").trim().toUpperCase();
  const badge = document.getElementById("add-acc-proxy-pool-avail-badge");
  const statusEl = document.getElementById("add-acc-proxy-pool-status");
  const providerId = document.getElementById("add-acc-proxy-provider-select")?.value || "auto";

  if (!region) {
    if (badge) { badge.textContent = "Region needed"; badge.className = "badge text-xs badge-status-off"; }
    if (statusEl) {
      statusEl.classList.remove("hidden");
      statusEl.innerHTML = `<span class="text-warning">Select or type an account region/country code first (e.g. DE, NL, US).</span>`;
    }
    return;
  }

  if (badge) { badge.textContent = "Checking..."; badge.className = "badge text-xs"; }
  try {
    const res = await api("proxy_availability", { country: region, provider_id: providerId });
    const count = res.available || 0;
    if (badge) {
      if (count > 0) {
        badge.textContent = `${count} sessions free`;
        badge.className = "badge text-xs badge-status-running";
      } else {
        badge.textContent = "0 sessions";
        badge.className = "badge text-xs badge-status-off";
      }
    }
    if (statusEl) {
      statusEl.classList.remove("hidden");
      if (count > 0) {
        statusEl.innerHTML = `<span class="text-success">✅ ${count} proxy session(s) available for ${getCountryFlag(region)} ${region}.</span>`;
      } else {
        statusEl.innerHTML = `<span class="text-danger">⚠️ No free sessions for ${getCountryFlag(region)} ${region} in this provider. Add sessions in Proxy Pools or choose another provider.</span>`;
      }
    }
  } catch (err) {
    if (badge) { badge.textContent = "Unavailable"; badge.className = "badge text-xs badge-status-off"; }
    if (statusEl) {
      statusEl.classList.remove("hidden");
      statusEl.innerHTML = `<span class="text-danger">⚠️ ${escapeHtml(err.message)}</span>`;
    }
  }
}

async function runAutoHealProxies() {
  const btns = Array.from(document.querySelectorAll("#btn-auto-heal-accounts, #btn-auto-heal-proxies"));
  btns.forEach(b => setButtonLoading(b, true, "Auto-Fixing..."));
  showToast("Scanning accounts & auto-allocating working proxies from pool...", "info");
  try {
    const res = await api("auto_heal_proxies", {});
    const healedCount = res.healed_count || 0;
    const failedCount = res.failed_count || 0;
    if (healedCount > 0) {
      showToast(`🎉 Successfully auto-fixed ${healedCount} account(s) with working proxies!`, "success");
    } else if (failedCount > 0) {
      showToast(`Auto-fix could not find working proxies for ${failedCount} account(s). Check pool capacity.`, "warning");
    } else {
      showToast("All accounts already have working proxy connections.", "success");
    }
    await loadAll();
  } catch (err) {
    showToast(`Auto-fix failed: ${err.message}`, "error");
  } finally {
    btns.forEach(b => setButtonLoading(b, false));
  }
}

async function replaceAccountProxy(accId, btnEl = null) {
  const account = state.accounts.find(item => String(item.id) === String(accId));
  if (!account || !account.has_proxy) {
    showToast("This account does not have a proxy route to replace.", "info");
    return;
  }
  const btn = btnEl || document.getElementById(`btn-replace-proxy-${accId}`);
  await runWithButtonLoading(btn, async () => {
    state.recoveryStatus[accId] = { status: "retrying" };
    renderAccountsManagement();
    try {
      const result = await api("auto_heal_proxies", { account_id: account.id, force: true }, { retryMode: "never" });
      const healed = result && Array.isArray(result.healed) && result.healed.some(item => String(item.id) === String(account.id));
      state.recoveryStatus[accId] = healed
        ? { status: "recovered", result, proxyReplaced: true }
        : { status: "unresolved", result, error: "No working replacement proxy was found" };
      showToast(healed ? `Proxy replaced for ${account.label}.` : `No working replacement was found for ${account.label}.`, healed ? "success" : "warning");
      await loadAll(true);
    } catch (err) {
      state.recoveryStatus[accId] = { status: "unresolved", error: err.message };
      renderAccountsManagement();
      showToast(`Proxy replacement failed: ${err.message}`, "error");
    }
  }, "Replacing...");
}
window.replaceAccountProxy = replaceAccountProxy;

function parseSessionIdsFromText(text, templateUsername = null) {
  if (!text) return [];
  const lines = text.split("\n").map(l => l.trim()).filter(Boolean);
  const found = [];

  let tplRegex = null;
  if (templateUsername && templateUsername.includes("{session}")) {
    let pat = templateUsername.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    pat = pat.replace(/\\\{country\\\}/g, '(?:[A-Za-z]{2}|[A-Za-z0-9_-]+?)');
    pat = pat.replace(/\\\{session\\\}/g, '([A-Za-z0-9_-]+)');
    try {
      tplRegex = new RegExp(pat);
    } catch (e) {
      tplRegex = null;
    }
  }

  for (let line of lines) {
    // 1. Skip standalone line numbers / list indices like "1", "2.", "#3", "4)"
    if (/^#?\d+[.):]?\s*$/.test(line)) {
      continue;
    }
    // 2. Strip leading numbers on a proxy line e.g. "1. niceproxy.io..." or "1 niceproxy.io..."
    line = line.replace(/^\s*#?\d+[.):\s]+\s*(?=[a-zA-Z0-9]+:\/\/|[a-zA-Z0-9.-]+:\d+)/, "");

    // 3. Extract user candidate
    let userCandidate = null;
    if (line.includes("@")) {
      const parts = line.split("@");
      const beforeAt = parts[0].includes("://") ? parts[0].split("://")[1] : parts[0];
      if (beforeAt.includes(":") && !/^\d+$/.test(beforeAt.split(":")[1])) {
        userCandidate = beforeAt.split(":")[0];
      } else if (parts[1] && parts[1].includes(":")) {
        userCandidate = parts[1].split(":")[0];
      }
    } else if (line.includes(":")) {
      const parts = line.split(":");
      if (parts.length >= 4) {
        userCandidate = parts[2];
      } else if (parts.length === 3) {
        userCandidate = parts[1];
      }
    }

    const targetText = userCandidate || line;

    // 4. Try template regex
    if (tplRegex) {
      const m = targetText.match(tplRegex) || line.match(tplRegex);
      if (m && m[1]) {
        found.push(m[1]);
        continue;
      }
    }

    // 5. Try heuristic session pattern
    const m = targetText.match(/(?:ssid|sid|session)[_-]([a-zA-Z0-9_-]+?)(?:_(?:time|life|sst)|-(?:sst|time)|[:@/\s]|$)/i) ||
              targetText.match(/(?:ssid|sid|session)[_-]([a-zA-Z0-9_-]+)/i);
    if (m && m[1]) {
      found.push(m[1]);
      continue;
    }

    // 6. User candidate with country tag
    if (userCandidate && userCandidate !== line) {
      const mc = userCandidate.match(/country[_-][A-Za-z]{2}[_-]([a-zA-Z0-9_-]+)/i);
      if (mc && mc[1]) {
        found.push(mc[1]);
        continue;
      }
      found.push(userCandidate);
      continue;
    }

    // 7. Single clean token
    const token = line.replace(/[^a-zA-Z0-9_\-]/g, "");
    if (token) {
      found.push(token);
    }
  }

  return [...new Set(found)];
}

function updateBulkSessionsPreview(text) {
  const sel = document.getElementById("bulk-sessions-provider");
  const pid = sel ? parseInt(sel.value, 10) : null;
  const prov = pid ? state.proxyProviders.find(p => p.id === pid) : null;
  const tplUser = prov?.template_public?.username || prov?.template?.username || null;

  const ids = parseSessionIdsFromText(text, tplUser);
  const badge = document.getElementById("bulk-sessions-count-badge");
  const prev = document.getElementById("bulk-sessions-preview");
  if (badge) {
    badge.textContent = `${ids.length} session${ids.length === 1 ? '' : 's'} detected`;
    badge.className = ids.length > 0 ? "badge badge-status-running text-xs" : "badge badge-status-off text-xs";
  }
  if (prev) {
    if (ids.length === 0) {
      prev.textContent = "Paste proxy lines above to preview extracted session tokens.";
    } else {
      prev.innerHTML = ids.map((id, idx) => `<span class="badge badge-vultr font-mono text-xs mr-1 mb-1">${idx+1}. ${escapeHtml(id)}</span>`).join(" ");
    }
  }
}

function openBulkSessionsModal(preselectedPid = null) {
  const sel = document.getElementById("bulk-sessions-provider");
  if (sel) {
    sel.innerHTML = state.proxyProviders.map(p =>
      `<option value="${p.id}" ${p.id === preselectedPid ? 'selected' : ''}>${escapeHtml(p.label)} (${escapeHtml(p.template_public?.host || 'host')})</option>`
    ).join("");
  }
  const input = document.getElementById("bulk-sessions-input");
  if (input) input.value = "";
  updateBulkSessionsPreview("");
  openModal("modal-add-proxy-sessions");
}

function formatAccountProxyLabel(acc) {
  if (acc.binding) {
    return `🔀 Pool (${acc.binding.country || acc.region || 'Auto'}: ${acc.binding.session_id.substring(0, 8)}…)`;
  }
  if (acc.has_proxy) {
    return `🛡️ ${acc.proxy_masked || 'Custom Proxy'}`;
  }
  return `🌐 Direct Egress`;
}

function getAccountFailureStatus(accId) {
  const err = (state.accountErrors && (state.accountErrors[accId] || state.accountErrors[String(accId)])) ||
              (state.accountBilling && state.accountBilling[accId] && state.accountBilling[accId].status === "error" && state.accountBilling[accId].error);
  if (!err) return null;
  const str = String(err);
  const isProxy = window.CloudbotSync.proxyFailure(str);
  return {
    isProxy: isProxy,
    error: str,
    title: isProxy ? "Proxy Failed" : "Connection Error",
    shortMessage: isProxy ? "Proxy Failed" : "Error"
  };
}

function initSyncManager() {
  if (syncManager) return syncManager;
  syncManager = window.CloudbotSync.createManager({
    resourceNames: ["accounts", "billing", "proxyProviders", "servers", "floatingIps", "primaryIps", "sshKeys", "dnsZones", "watchdog", "tunnels"],
    freshForMs: 300000,
    onState: (snapshot) => {
      state.syncSnapshot = snapshot;
      renderSyncStatus(snapshot);
    }
  });
  renderSyncStatus(syncManager.snapshot());
  const stripRefresh = document.getElementById("btn-sync-strip-refresh");
  if (stripRefresh) stripRefresh.addEventListener("click", () => loadAll(true));
  document.addEventListener("visibilitychange", () => {
    const isSyncing = state.syncSnapshot && Object.values(state.syncSnapshot.resources || {}).some(item => item.status === "syncing");
    if (!document.hidden && syncManager && state.syncSnapshot && !state.syncSnapshot.fresh && !isSyncing) {
      loadAll(true);
    }
  });
  return syncManager;
}

function renderSyncStatus(snapshot) {
  const strip = document.getElementById("sync-status-strip");
  const label = document.getElementById("sync-status-label");
  const detail = document.getElementById("sync-status-detail");
  const badge = document.getElementById("sync-attention-badge");
  const refresh = document.getElementById("btn-sync-strip-refresh");
  const sidebarConnection = document.getElementById("connection-status-text");
  const sidebarDot = document.querySelector(".sidebar-footer .status-dot");
  if (!strip || !snapshot) return;

  const statuses = Object.values(snapshot.resources || {});
  const hasStarted = snapshot.generation > 0;
  const syncing = statuses.some(item => item.status === "syncing");
  const attention = snapshot.attentionCount || 0;
  const failedResources = Object.entries(snapshot.resources || {})
    .filter(([, item]) => item.status === "stale" || item.status === "error")
    .map(([name]) => name.replace(/([A-Z])/g, " $1").replace(/^./, ch => ch.toUpperCase()));
  const stateName = !hasStarted ? "idle" : syncing ? "syncing" : attention ? "attention" : snapshot.fresh ? "synced" : "stale";
  strip.dataset.state = stateName;
  if (sidebarConnection) sidebarConnection.textContent = !hasStarted ? "Waiting" : syncing ? "Syncing" : attention ? "Needs attention" : snapshot.fresh ? "Connected" : "Cached data";
  if (sidebarDot) sidebarDot.className = `status-dot ${!hasStarted ? "idle" : attention ? "offline" : syncing ? "idle" : "online"}`;
  if (label) label.textContent = !hasStarted ? "Waiting for first sync" : syncing ? "Syncing cloud data" : attention ? "Needs attention" : snapshot.fresh ? "All data is up to date" : "Data may be stale";
  if (detail) {
    const when = snapshot.lastSuccessAt ? formatRelativeTime(snapshot.lastSuccessAt) : "No successful sync yet";
    detail.textContent = !hasStarted ? "Your cached data will appear here." : syncing ? "Keeping the last known values visible while live data arrives." : attention ? `${failedResources.join(", ")} need attention · Last successful sync ${when}.` : `Last successful sync ${when}.`;
  }
  if (badge) {
    badge.textContent = `${attention} need attention`;
    badge.classList.toggle("hidden", attention === 0);
  }
  if (refresh) {
    refresh.disabled = syncing;
    refresh.textContent = syncing ? "Refreshing…" : "Refresh now";
  }
}

function formatRelativeTime(timestamp) {
  const age = Math.max(0, Date.now() - Number(timestamp));
  if (age < 10000) return "just now";
  if (age < 60000) return `${Math.floor(age / 1000)}s ago`;
  if (age < 3600000) return `${Math.floor(age / 60000)}m ago`;
  return `${Math.floor(age / 3600000)}h ago`;
}

async function retryResource(resourceName) {
  const label = String(resourceName || "cloud data").replace(/([A-Z])/g, " $1").toLowerCase();
  showToast(`Refreshing ${label}…`, "info");
  return loadAll(true);
}

async function recoverFailedProxy(generation, account, error) {
  const key = `${generation}:${account && account.id}`;
  if (proxyRecoveryInFlight.has(key)) return proxyRecoveryInFlight.get(key);
  const operation = performFailedProxyRecovery(generation, account, error);
  proxyRecoveryInFlight.set(key, operation);
  try {
    return await operation;
  } finally {
    if (proxyRecoveryInFlight.get(key) === operation) proxyRecoveryInFlight.delete(key);
  }
}

async function performFailedProxyRecovery(generation, account, error) {
  if (!syncManager || !syncManager.current(generation)) return { status: "not-applicable" };
  state.recoveryStatus[account.id] = { status: "retrying", error: String(error || "") };
  renderAccountsManagement();
  try {
    const retry = await api("test_account", { account_id: account.id }, { retryMode: "read" });
    if (!syncManager.current(generation)) return { status: "not-applicable" };
    if (retry && retry.status !== "error") {
      const result = { status: "recovered", result: retry, proxyReplaced: false, error: null };
      state.recoveryStatus[account.id] = result;
      return result;
    }
    if (!window.CloudbotSync.proxyFailure(retry && retry.error)) {
      const result = { status: "unresolved", result: retry, error: retry && retry.error || "The account retry failed" };
      state.recoveryStatus[account.id] = result;
      return result;
    }
    error = retry.error;
  } catch (retryError) {
    if (!syncManager.current(generation)) return { status: "not-applicable" };
    if (!window.CloudbotSync.proxyFailure(retryError)) {
      const result = { status: "unresolved", result: null, error: retryError.message || String(retryError) };
      state.recoveryStatus[account.id] = result;
      return result;
    }
    error = retryError;
  }
  const result = await syncManager.recoverProxy({
    generation,
    account,
    error,
    healProxy: (acc) => api("auto_heal_proxies", { account_id: acc.id, force: true }, { retryMode: "never" }),
    retryRead: () => api("test_account", { account_id: account.id }, { retryMode: "read" })
  });
  if (!syncManager.current(generation)) return { status: "not-applicable" };
  state.recoveryStatus[account.id] = result;
  return result;
}

// ==================== DATA LOADER ====================
async function loadAll(forceRefresh = false) {
  const manager = initSyncManager();
  state.recoveryStatus = {};
  state.liveAccountFailures = {};
  const generation = manager.begin();
  const refreshBtn = document.getElementById("btn-refresh-all");
  if (refreshBtn) {
    refreshBtn.classList.add("loading");
    refreshBtn.disabled = true;
    refreshBtn.setAttribute("aria-busy", "true");
  }

  try {
    await loadAllPhase(generation, false);
    if (!manager.current(generation) || !state.authenticated) return;
    renderAllViews();
    updateBadges();

    manager.startPhase(generation);
    await loadAllPhase(generation, true);
    if (!manager.current(generation) || !state.authenticated) return;

    await autoRecoverFailedAccounts(generation);
    if (!manager.current(generation)) return;
    renderAllViews();
    updateBadges();
    if (forceRefresh) showToast("Live cloud data and balances refreshed successfully!", "success");
  } catch (err) {
    if (manager.current(generation)) showToast("Error loading data: " + err.message, "error");
  } finally {
    if (manager.current(generation) && refreshBtn) {
      refreshBtn.classList.remove("loading");
      refreshBtn.disabled = false;
      refreshBtn.removeAttribute("aria-busy");
    }
  }
}

async function loadAllPhase(generation, forceRefresh) {
  if (!syncManager.current(generation) || !state.authenticated) return;
  const refreshArg = forceRefresh ? { refresh: true } : {};
  const recordLiveFailure = (accountId, error) => {
    if (!forceRefresh || accountId === undefined || accountId === null || !error) return;
    const key = String(accountId);
    const existing = state.liveAccountFailures[key];
    if (!existing || window.CloudbotSync.proxyFailure(error)) state.liveAccountFailures[key] = error;
  };
  const apply = (resource, value, handler) => {
    if (!syncManager.current(generation) || !state.authenticated) return false;
    const accepted = forceRefresh
      ? syncManager.apply(generation, resource, value)
      : syncManager.hydrate(generation, resource, value);
    if (!accepted) return false;
    handler(value);
    renderAllViews();
    updateBadges();
    return true;
  };

  const observe = (resource, request, handler) => request.then(value => {
    apply(resource, value, handler);
  }).catch(error => {
    if (syncManager.current(generation) && state.authenticated) {
      syncManager.fail(generation, resource, error);
      renderAllViews();
      updateBadges();
    }
  });

  await Promise.all([
    observe("accounts", api("accounts", {}, { retryMode: "read" }), data => { state.accounts = data.accounts || []; }),
    observe("proxyProviders", api("proxy_providers", {}, { retryMode: "read" }), data => { state.proxyProviders = data.providers || []; }),
    observe("sshKeys", api("ssh_keys", {}, { retryMode: "read" }), data => { state.sshKeys = data.ssh_keys || []; }),
    observe("watchdog", api("watch_status", {}, { retryMode: "read" }), data => { state.watchdog = data; }),
    observe("tunnels", api("tunnels", {}, { retryMode: "read" }), data => { state.tunnels = data.tunnels || []; }),
    observe("servers", api("all_servers", refreshArg, { retryMode: "read" }), data => {
    state.servers = data.servers || [];
    state.accountErrors = data.account_errors || {};
    if (forceRefresh) {
      Object.entries(state.accountErrors).forEach(([id, error]) => recordLiveFailure(id, error));
    }
    if (Object.keys(state.accountErrors).length > 0) {
      syncManager.fail(generation, "servers", "One or more account server lists could not be refreshed", true);
    }
    }),
    observe("floatingIps", api("all_floating_ips", refreshArg, { retryMode: "read" }), data => { state.floatingIps = data.floating_ips || []; }),
    observe("dnsZones", api("dns_zones", {}, { retryMode: "read" }), data => { state.dnsZones = data.zones || []; }),
    observe("billing", api("check_all_accounts", refreshArg, { retryMode: "read" }), data => {
    if (!data || !data.accounts) return;
    for (const item of data.accounts) {
      if (item.account && item.account.id) {
        state.accountBilling[item.account.id] = {
          status: item.status,
          info: item.info,
          identity: item.identity,
          error: item.error,
          lastChecked: new Date()
        };
        if (forceRefresh) {
          const id = String(item.account.id);
          if (item.status === "error") recordLiveFailure(id, item.error || "Account check failed");
        }
      }
    }
    if (data.accounts.some(item => item.status === "error")) {
      syncManager.fail(generation, "billing", "One or more account checks failed", true);
    }
    })
  ]);
  if (!syncManager.current(generation) || !state.authenticated) return;

  const hetznerAccs = state.accounts.filter(a => a.provider === "hetzner");
  if (hetznerAccs.length === 0) {
    if (forceRefresh) syncManager.apply(generation, "primaryIps", []);
    else syncManager.hydrate(generation, "primaryIps", []);
    state.primaryIps = [];
    renderAllViews();
    updateBadges();
    return;
  }

  const primaryResults = await Promise.allSettled(
    hetznerAccs.map(h => api("hetzner_primary_ips", { account_id: h.id, ...refreshArg }, { retryMode: "read" }).then(res => ({ h, res })))
  );
  if (!syncManager.current(generation) || !state.authenticated) return;

  const pIps = [];
  let primarySuccess = false;
  for (const pr of primaryResults) {
    if (pr.status === "fulfilled" && pr.value && pr.value.res && pr.value.res.primary_ips) {
      primarySuccess = true;
      const { h, res } = pr.value;
      res.primary_ips.forEach(p => {
        p.provider = "hetzner";
        p.account_id = h.id;
        p.account_label = h.label;
        pIps.push(p);
      });
    }
  }
  if (primarySuccess) {
    if (forceRefresh) syncManager.apply(generation, "primaryIps", pIps);
    else syncManager.hydrate(generation, "primaryIps", pIps);
    state.primaryIps = pIps;
  } else {
    syncManager.fail(generation, "primaryIps", "Hetzner Primary IP data could not be refreshed", true);
  }
  renderOverview();
  renderIPManagement();
  renderHetznerHub();
  updateBadges();
}

async function autoRecoverFailedAccounts(generation) {
  const failures = new Map(Object.entries(state.liveAccountFailures || {}));

  let recoveredCount = 0;
  let replacedCount = 0;
  let serverRetryNeeded = false;
  for (const account of state.accounts) {
    if (!syncManager.current(generation)) return;
    const error = failures.get(String(account.id));
    if (!error || !account.has_proxy || !window.CloudbotSync.proxyFailure(error)) continue;
    const result = await recoverFailedProxy(generation, account, error);
    if (!syncManager.current(generation)) return;
    if (result.status !== "recovered") continue;
    recoveredCount += 1;
    if (result.proxyReplaced) replacedCount += 1;
    if (state.accountErrors && state.accountErrors[account.id]) serverRetryNeeded = true;
    const data = result.result;
    if (data && data.status === "ok") {
      state.accountBilling[account.id] = {
        status: data.status,
        info: data.info,
        identity: data.identity,
        latency_ms: data.latency_ms,
        error: null,
        lastChecked: new Date()
      };
      delete state.accountErrors[account.id];
      delete state.accountErrors[String(account.id)];
      delete state.liveAccountFailures[String(account.id)];
    }
  }
  if (serverRetryNeeded && syncManager.current(generation)) {
    try {
      const serverResult = await api("all_servers", { refresh: true }, { retryMode: "read" });
      if (serverResult && syncManager.current(generation)) {
        state.servers = serverResult.servers || state.servers;
        state.accountErrors = serverResult.account_errors || {};
        syncManager.apply(generation, "servers", serverResult);
      }
    } catch (error) {
      syncManager.fail(generation, "servers", error, true);
    }
  }
  const billingStillFailed = Object.values(state.accountBilling || {}).some(item => item && item.status === "error");
  const syncState = syncManager.snapshot();
  if (syncState.resources.billing && syncState.resources.billing.hasValue && !billingStillFailed) {
    syncManager.succeed(generation, "billing");
  }
  if (serverRetryNeeded && syncState.resources.servers && syncState.resources.servers.hasValue && Object.keys(state.accountErrors || {}).length === 0) {
    syncManager.succeed(generation, "servers");
  }
  if (recoveredCount > 0) {
    renderAllViews();
    const replacementText = replacedCount > 0 ? ` Replaced ${replacedCount} proxy route${replacedCount === 1 ? "" : "s"}.` : "";
    showToast(`Connection recovered for ${recoveredCount} account${recoveredCount === 1 ? "" : "s"}.${replacementText}`, "success");
  }
}

function updateBadges() {
  const hetznerServers = state.servers.filter(s => s.provider === "hetzner");
  const vultrServers = state.servers.filter(s => s.provider === "vultr");
  const linodeServers = state.servers.filter(s => s.provider === "linode");

  const bTotal = document.getElementById("badge-total-servers");
  const bAccounts = document.getElementById("badge-accounts-count");
  const bProxies = document.getElementById("badge-proxies-count");
  const bHetzner = document.getElementById("badge-hetzner-count");
  const bVultr = document.getElementById("badge-vultr-count");
  const bLinode = document.getElementById("badge-linode-count");
  const bFips = document.getElementById("badge-fips-count");
  const bSsh = document.getElementById("badge-ssh-count");

  if (bTotal) bTotal.textContent = state.servers.length;
  if (bAccounts) bAccounts.textContent = state.accounts.length;
  if (bProxies) bProxies.textContent = state.proxyProviders.length;
  if (bHetzner) bHetzner.textContent = hetznerServers.length;
  if (bVultr) bVultr.textContent = vultrServers.length;
  if (bLinode) bLinode.textContent = linodeServers.length;
  if (bFips) bFips.textContent = state.floatingIps.length + state.primaryIps.length;
  if (bSsh) bSsh.textContent = state.sshKeys.length;
}

// ==================== RENDER VIEWS ====================
function renderAllViews() {
  renderOverview();
  renderAccountsManagement();
  renderProxyManagement();
  renderHetznerHub();
  renderVultrHub();
  renderLinodeHub();
  renderAllCompute();
  renderIPManagement();
  renderSSHKeys();
  renderDNS();
  renderWatchdog();
}

function getProviderBadge(provider) {
  const provKey = (provider || "").toLowerCase();
  const p = PROVIDERS[provKey] || { name: provider || "Cloud", logo: "/ui/assets/cloud.svg", badgeClass: "badge-hetzner" };
  return `<span class="badge ${p.badgeClass}"><img src="${p.logo}" alt="${p.name}" width="14" height="14" class="w-3.5 h-3.5 object-contain" style="width:14px;height:14px;object-fit:contain;flex-shrink:0;"> ${p.name}</span>`;
}

// ---- TAB 1: EXECUTIVE OVERVIEW ----
function renderOverview() {
  const elTotalInstances = document.getElementById("stat-total-instances");
  if (elTotalInstances) elTotalInstances.textContent = state.servers.length;
  const elTotalFips = document.getElementById("stat-total-fips");
  if (elTotalFips) elTotalFips.textContent = state.floatingIps.length + state.primaryIps.length;
  const elTotalAccounts = document.getElementById("stat-total-accounts");
  if (elTotalAccounts) elTotalAccounts.textContent = state.accounts.length;
  const elTotalSsh = document.getElementById("stat-total-ssh");
  if (elTotalSsh) elTotalSsh.textContent = state.sshKeys.length;

  // Hetzner Metrics
  const hAccs = state.accounts.filter(a => a.provider === "hetzner");
  const hSrvs = state.servers.filter(s => s.provider === "hetzner");
  const hFips = state.floatingIps.filter(f => f.provider === "hetzner").length + state.primaryIps.length;
  document.getElementById("hub-hetzner-servers").textContent = hSrvs.length;
  document.getElementById("hub-hetzner-accounts").textContent = hAccs.length;
  document.getElementById("hub-hetzner-fips").textContent = hFips;

  const hChips = document.getElementById("hub-hetzner-account-chips");
  hChips.innerHTML = hAccs.length > 0
    ? hAccs.map(a => `<span class="hub-account-chip" onclick="navigateToAccount('hetzner', ${a.id})" style="cursor: pointer;" title="View instances for ${escapeHtml(a.label)}">${escapeHtml(a.label)} (${hSrvs.filter(s => s.account_id === a.id).length})</span>`).join("")
    : `<span class="text-xs text-muted">No accounts added</span>`;

  // Vultr Metrics
  const vAccs = state.accounts.filter(a => a.provider === "vultr");
  const vSrvs = state.servers.filter(s => s.provider === "vultr");
  const vFips = state.floatingIps.filter(f => f.provider === "vultr").length;
  document.getElementById("hub-vultr-servers").textContent = vSrvs.length;
  document.getElementById("hub-vultr-accounts").textContent = vAccs.length;
  document.getElementById("hub-vultr-fips").textContent = vFips;

  const vChips = document.getElementById("hub-vultr-account-chips");
  vChips.innerHTML = vAccs.length > 0
    ? vAccs.map(a => `<span class="hub-account-chip" onclick="navigateToAccount('vultr', ${a.id})" style="cursor: pointer;" title="View instances for ${escapeHtml(a.label)}">${escapeHtml(a.label)} (${vSrvs.filter(s => s.account_id === a.id).length})</span>`).join("")
    : `<span class="text-xs text-muted">No accounts added</span>`;

  // Linode Metrics
  const lAccs = state.accounts.filter(a => a.provider === "linode");
  const lSrvs = state.servers.filter(s => s.provider === "linode");
  document.getElementById("hub-linode-servers").textContent = lSrvs.length;
  document.getElementById("hub-linode-accounts").textContent = lAccs.length;

  const lChips = document.getElementById("hub-linode-account-chips");
  lChips.innerHTML = lAccs.length > 0
    ? lAccs.map(a => `<span class="hub-account-chip" onclick="navigateToAccount('linode', ${a.id})" style="cursor: pointer;" title="View instances for ${escapeHtml(a.label)}">${escapeHtml(a.label)} (${lSrvs.filter(s => s.account_id === a.id).length})</span>`).join("")
    : `<span class="text-xs text-muted">No accounts added</span>`;
}

// ==================== LIVE BILLING REFRESH ====================
async function refreshAllBillingDetails(silent = false) {
  const icon = document.getElementById("refresh-billing-icon");
  const btn = document.getElementById("btn-refresh-all-billing");

  await runWithButtonLoading(btn, async () => {
    if (icon) icon.classList.add("spinning");
    try {
      if (!silent) showToast("Querying real-time billing and account balances...", "info");
      const res = await api("check_all_accounts", { refresh: true });
      if (res && res.accounts) {
        const generation = syncManager ? syncManager.snapshot().generation : 0;
        for (let itemIndex = 0; itemIndex < res.accounts.length; itemIndex += 1) {
          let item = res.accounts[itemIndex];
          const account = item.account && state.accounts.find(acc => String(acc.id) === String(item.account.id));
          if (item.status === "error" && account && account.has_proxy && window.CloudbotSync.proxyFailure(item.error)) {
            const recovery = await recoverFailedProxy(generation, account, item.error);
            if (recovery.status === "recovered" && recovery.result && recovery.result.status === "ok") {
              item = Object.assign({}, item, recovery.result, { status: "ok", error: null });
              res.accounts[itemIndex] = item;
            }
          }
          if (item.account && item.account.id) {
            state.accountBilling[item.account.id] = {
              status: item.status,
              info: item.info,
              identity: item.identity,
              latency_ms: item.latency_ms,
              error: item.error,
              lastChecked: new Date()
            };
            state.accountErrors = state.accountErrors || {};
            if (item.status === "error") {
              state.accountErrors[item.account.id] = item.error;
              state.accountErrors[String(item.account.id)] = item.error;
            } else {
              delete state.accountErrors[item.account.id];
              delete state.accountErrors[String(item.account.id)];
            }
          }
        }
        renderAccountsManagement();
        renderHetznerHub();
        renderVultrHub();
        renderLinodeHub();
        if (!silent) showToast("Live billing & balances updated successfully!", "success");
      }
    } catch (err) {
      if (!silent) showToast("Failed to refresh billing: " + err.message, "error");
    } finally {
      if (icon) icon.classList.remove("spinning");
    }
  }, "Refreshing...");
}

async function refreshSingleAccountBilling(accId, btnEl = null) {
  const btn = btnEl || document.getElementById(`btn-refresh-billing-${accId}`) || document.getElementById(`btn-check-status-${accId}`) || document.getElementById(`btn-check-status-drilldown-${accId}`);
  await runWithButtonLoading(btn, async () => {
    try {
      let res = await api("test_account", { account_id: accId }, { retryMode: "read" });
      const account = state.accounts.find(item => String(item.id) === String(accId));
      if (res.status === "error" && account && account.has_proxy && window.CloudbotSync.proxyFailure(res.error)) {
        const recovery = await recoverFailedProxy(syncManager.snapshot().generation, account, res.error);
        if (recovery.status === "recovered" && recovery.result) res = recovery.result;
      }
      state.accountBilling[accId] = {
        status: res.status,
        info: res.info,
        identity: res.identity,
        latency_ms: res.latency_ms,
        error: res.error,
        lastChecked: new Date()
      };
      state.accountErrors = state.accountErrors || {};
      if (res.status === "error") {
        state.accountErrors[accId] = res.error;
        state.accountErrors[String(accId)] = res.error;
        const isProxy = window.CloudbotSync.proxyFailure(res.error || "");
        showToast(isProxy ? `⚠️ Proxy failed for account #${accId}: ${res.error}` : `Connection error for account #${accId}: ${res.error}`, "error");
      } else {
        delete state.accountErrors[accId];
        delete state.accountErrors[String(accId)];
        showToast(`Account #${accId} verified (${res.identity || 'OK'})`, "success");
        try {
          const sRes = await api("all_servers");
          if (sRes.servers) state.servers = sRes.servers;
        } catch (e) {}
      }
      renderAllViews();
    } catch (err) {
      state.accountErrors = state.accountErrors || {};
      state.accountErrors[accId] = err.message;
      state.accountErrors[String(accId)] = err.message;
      renderAllViews();
      showToast(`Billing check failed: ${err.message}`, "error");
    }
  });
}

// ==================== TAB: ACCOUNT MANAGEMENT & BILLING ====================
function filterAccountsByProvider(provider) {
  state.activeAccountFilter = provider;
  document.querySelectorAll("#account-provider-filters .pill-filter").forEach(b => {
    b.classList.toggle("active", b.dataset.filter === provider);
  });
  renderAccountsManagement();
}

function filterAccountsList() {
  const input = document.getElementById("search-accounts-input");
  state.accountSearchQuery = (input ? input.value : "").trim().toLowerCase();
  renderAccountsManagement();
}

function formatAccountBillingDetails(acc, b, fail) {
  if (fail) {
    const isProxy = fail.isProxy;
    return {
      balanceDisplay: `<span class="text-danger font-bold text-xs">⚠️ ${escapeHtml(isProxy ? 'Proxy Failed' : 'Connection Error')}</span>`,
      usageDisplay: null,
      balanceText: isProxy ? '⚠️ Proxy Failed' : '⚠️ Connection Error',
      usageText: null,
      badge: `<span class="badge badge-danger">⚠️ Proxy Failed</span>`,
      isCredit: false,
    };
  }

  if (!b || !b.info) {
    if (b && b.status === "error") {
      return {
        balanceDisplay: `<span class="text-danger font-bold text-xs" title="${escapeHtml(b.error || '')}">⚠️ Auth / Proxy Error</span>`,
        usageDisplay: null,
        balanceText: "Auth / Proxy error",
        usageText: null,
        badge: `<span class="badge badge-danger">⚠️ Error</span>`,
        isCredit: false,
      };
    }
    return {
      balanceDisplay: `<span class="text-secondary text-xs">Live details ready</span>`,
      usageDisplay: null,
      balanceText: "Live Details Ready",
      usageText: null,
      badge: null,
      isCredit: false,
    };
  }

  const info = b.info;
  if (acc.provider === "linode") {
    const credit = Number(info.credit || 0);
    const bal = Number(info.balance || 0);
    const pending = Number(info.pending_charges || 0);
    const isCredit = credit > 0 || bal < 0;

    let balanceDisplay = "";
    let balanceText = "";
    let badgeText = "";
    if (credit > 0) {
      balanceDisplay = `<span class="text-success font-bold">$${credit.toFixed(2)} credit</span>`;
      balanceText = `$${credit.toFixed(2)} credit`;
      badgeText = `$${credit.toFixed(2)} credit`;
    } else if (bal > 0) {
      balanceDisplay = `<span class="text-danger font-bold">$${bal.toFixed(2)} owed</span>`;
      balanceText = `$${bal.toFixed(2)} owed`;
      badgeText = `$${bal.toFixed(2)} owed`;
    } else if (bal < 0) {
      balanceDisplay = `<span class="text-success font-bold">$${Math.abs(bal).toFixed(2)} credit</span>`;
      balanceText = `$${Math.abs(bal).toFixed(2)} credit`;
      badgeText = `$${Math.abs(bal).toFixed(2)} credit`;
    } else {
      balanceDisplay = `<span class="text-primary font-bold">$0.00 bal</span>`;
      balanceText = `$0.00 bal`;
      badgeText = `$0.00 bal`;
    }

    const usageDisplay = pending > 0
      ? `<span class="text-secondary font-mono text-xs">$${pending.toFixed(2)} unbilled</span>`
      : `<span class="text-muted text-xs">$0.00 unbilled</span>`;
    const usageText = `$${pending.toFixed(2)} unbilled`;

    const badge = `<span class="badge ${isCredit ? 'badge-status-running' : (bal > 0 ? 'badge-danger' : 'badge-linode')} font-mono text-xs">${badgeText}</span>`;

    return {
      balanceDisplay,
      usageDisplay,
      balanceText,
      usageText,
      badge,
      isCredit,
    };
  }

  if (acc.provider === "vultr") {
    const bal = Number(info.balance || 0);
    const pending = Number(info.pending_charges || 0);
    const isCredit = bal < 0;

    let balanceDisplay = "";
    let balanceText = "";
    let badgeText = "";
    if (isCredit) {
      balanceDisplay = `<span class="text-success font-bold">-$${Math.abs(bal).toFixed(2)} credit</span>`;
      balanceText = `-$${Math.abs(bal).toFixed(2)} credit`;
      badgeText = `-$${Math.abs(bal).toFixed(2)} credit`;
    } else if (bal > 0) {
      balanceDisplay = `<span class="text-danger font-bold">$${bal.toFixed(2)} owed</span>`;
      balanceText = `$${bal.toFixed(2)} owed`;
      badgeText = `$${bal.toFixed(2)} owed`;
    } else {
      balanceDisplay = `<span class="text-primary font-bold">$0.00 bal</span>`;
      balanceText = `$0.00 bal`;
      badgeText = `$0.00 bal`;
    }

    const usageDisplay = `<span class="text-secondary font-mono text-xs">$${pending.toFixed(2)} pending</span>`;
    const usageText = `$${pending.toFixed(2)} pending`;

    const badge = `<span class="badge ${isCredit ? 'badge-status-running' : (bal > 0 ? 'badge-danger' : 'badge-vultr')} font-mono text-xs">${badgeText}</span>`;

    return {
      balanceDisplay,
      usageDisplay,
      balanceText,
      usageText,
      badge,
      isCredit,
    };
  }

  if (acc.provider === "hetzner") {
    const monthly = Number(info.monthly_runrate || 0);
    const srvCount = Number(info.servers_count || 0);
    const balanceDisplay = `<span class="text-primary font-bold">€${monthly.toFixed(2)}/mo</span>`;
    const usageDisplay = `<span class="text-secondary font-mono text-xs">${srvCount} srv run-rate</span>`;
    const balanceText = `€${monthly.toFixed(2)}/mo (${srvCount} srv)`;
    const usageText = `${srvCount} srv run-rate`;
    const badge = `<span class="badge badge-hetzner font-mono text-xs">€${monthly.toFixed(2)}/mo</span>`;

    return {
      balanceDisplay,
      usageDisplay,
      balanceText,
      usageText,
      badge,
      isCredit: false,
    };
  }

  return {
    balanceDisplay: `<span class="text-secondary text-xs">Ready</span>`,
    usageDisplay: null,
    balanceText: "Ready",
    usageText: null,
    badge: null,
    isCredit: false,
  };
}

function renderAccountsManagement() {
  const totalAccs = state.accounts.length;
  const cAll = document.getElementById("filter-acc-count-all");
  const cHetz = document.getElementById("filter-acc-count-hetzner");
  const cVul = document.getElementById("filter-acc-count-vultr");
  const cLin = document.getElementById("filter-acc-count-linode");
  if (cAll) cAll.textContent = totalAccs;
  if (cHetz) cHetz.textContent = state.accounts.filter(a => a.provider === "hetzner").length;
  if (cVul) cVul.textContent = state.accounts.filter(a => a.provider === "vultr").length;
  if (cLin) cLin.textContent = state.accounts.filter(a => a.provider === "linode").length;

  const container = document.getElementById("accounts-master-grid");
  if (!container) return;

  let filtered = state.accounts;
  if (state.activeAccountFilter && state.activeAccountFilter !== "all") {
    filtered = filtered.filter(a => a.provider === state.activeAccountFilter);
  }
  if (state.accountSearchQuery) {
    const q = state.accountSearchQuery;
    filtered = filtered.filter(a =>
      (a.label && a.label.toLowerCase().includes(q)) ||
      String(a.id).includes(q) ||
      (a.region && a.region.toLowerCase().includes(q)) ||
      (a.proxy_masked && a.proxy_masked.toLowerCase().includes(q))
    );
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div class="col-span-full text-center py-12 text-secondary">No cloud accounts matched the selected filters. Click "+ Add Cloud Account" to add one.</div>`;
    return;
  }

  container.innerHTML = `
    <div class="accounts-clean-list">
      ${filtered.map(acc => {
        const p = PROVIDERS[acc.provider] || { name: acc.provider, logo: "/ui/assets/cloud.svg" };
        const b = state.accountBilling[acc.id];
        const fail = getAccountFailureStatus(acc.id);
        const recovery = state.recoveryStatus[acc.id];
        const hasChecked = !!b || !!fail;
        const isOk = !fail && b && b.status === "ok";
        const reg = formatRegion(acc.region);

        // Billing summary
        const bDetails = formatAccountBillingDetails(acc, b, fail);
        let billingText = bDetails.balanceText;
        if (acc.provider === "vultr" && bDetails.usageText) {
          billingText = `${bDetails.balanceText} · ${bDetails.usageText}`;
        }
        let billingClass = bDetails.isCredit ? "text-success font-bold" : (fail ? "text-danger font-bold" : "text-primary font-bold");

        const latPill = b && b.latency_ms !== undefined ? (
          b.latency_ms < 300 ? `<span class="latency-tag fast">⚡ ${b.latency_ms}ms</span>` :
          `<span class="latency-tag medium">⚡ ${b.latency_ms}ms</span>`
        ) : "";

        let subBillingText = latPill || 'Live status ready';
        if (fail) {
          subBillingText = `<span class="text-danger font-mono text-xs" title="${escapeHtml(fail.error)}">${escapeHtml(fail.error.length > 40 ? fail.error.substring(0, 38) + '…' : fail.error)}</span>`;
        }
        if (recovery && recovery.status === "retrying") {
          subBillingText = `<span class="text-warning text-xs">↻ Retrying proxy route…</span>`;
        } else if (recovery && recovery.status === "recovered") {
          const recoveryLabel = recovery.proxyReplaced ? "Proxy replaced" : "Connection recovered";
          subBillingText = `<span class="text-success text-xs">✓ ${recoveryLabel} ${formatRelativeTime(Date.now())}</span>`;
        } else if (recovery && recovery.status === "unresolved") {
          subBillingText = `<span class="text-warning text-xs" title="${escapeHtml(recovery.error || 'No working replacement proxy was found')}">⚠ Replacement needed</span>`;
        }

        // Proxy Route pill
        let proxyPill = "";
        if (fail && fail.isProxy) {
          proxyPill = `<span class="badge-proxy-custom" style="background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.4); color: #fca5a5;" title="${escapeHtml(fail.error)}">⚠️ Proxy Failed</span>`;
        } else if (acc.binding) {
          proxyPill = `<span class="badge-proxy-pool" title="Rotating session: ${escapeHtml(acc.binding.session_id)}">🔀 ${escapeHtml(acc.binding.country || acc.region || 'POOL')} · ${escapeHtml(acc.binding.session_id.substring(0, 8))}…</span>`;
        } else if (acc.has_proxy) {
          proxyPill = `<span class="badge-proxy-custom" title="${escapeHtml(acc.proxy_masked)}">🛡️ ${escapeHtml(acc.proxy_masked)}</span>`;
        } else {
          proxyPill = `<span class="badge-proxy-direct">🌐 Direct</span>`;
        }

        return `
          <div class="account-clean-row ${acc.provider}-row ${fail ? 'border-danger' : ''}" id="acc-card-${acc.id}">
            <!-- Col 1: Provider Logo + Label + ID -->
            <div class="account-clean-primary">
              <img src="${p.logo}" alt="${p.name}" class="account-clean-logo">
              <div class="account-clean-info">
                <div class="account-clean-title">
                  <span class="account-clean-label" title="${escapeHtml(acc.label)}">${escapeHtml(acc.label)}</span>
                  ${hasChecked ? (
                    isOk ? `<span class="status-dot online" title="Verified"></span>` :
                    `<span class="status-dot offline" title="${escapeHtml((fail ? fail.error : b.error) || 'Connection Error')}"></span>`
                  ) : `<span class="status-dot idle" title="Ready"></span>`}
                </div>
                <div class="account-clean-sub text-xs text-muted font-mono">
                  #${acc.id} · ${p.name}
                </div>
              </div>
            </div>

            <!-- Col 2: Region Tag -->
            <div class="account-clean-region">
              <button class="region-badge-btn" onclick="openEditRegionModal(${acc.id})" title="Edit region">
                <span>${reg.flag}</span>
                <span class="font-mono">${reg.code || 'Set Region'}</span>
                <span class="text-xs text-muted">✏️</span>
              </button>
            </div>

            <!-- Col 3: Proxy -->
            <div class="account-clean-proxy">
              ${proxyPill}
              <button class="btn btn-secondary btn-sm flex-shrink-0" onclick="openEditProxyModal(${acc.id})" title="Manage proxy route and pool">Manage pool</button>
            </div>

            <!-- Col 4: Live Billing & Latency -->
            <div class="account-clean-billing">
              <div class="billing-amount-wrap">
                <span class="${billingClass} text-sm billing-amount-text">${billingText}</span>
                <button class="btn-icon-subtle" id="btn-refresh-billing-${acc.id}" onclick="refreshSingleAccountBilling(${acc.id}, this)" title="Refresh account billing & test proxy">🔄</button>
              </div>
              <div class="text-xs text-secondary mt-0.5">${subBillingText}</div>
            </div>

            <!-- Col 5: Actions -->
            <div class="account-clean-actions">
              ${acc.provider === "linode" ? `<button class="btn btn-secondary btn-sm" onclick="openLinodePromoModal(${acc.id})" title="Apply Linode Promo Code">🎟 Promo</button>` : ''}
              <button class="btn btn-secondary btn-sm" id="btn-test-proxy-${acc.id}" onclick="testSingleAccountProxy(${acc.id}, this)" title="Retry connection">↻ Retry connection</button>
              ${acc.has_proxy ? `<button class="btn btn-warning btn-sm" id="btn-replace-proxy-${acc.id}" onclick="replaceAccountProxy(${acc.id}, this)" title="Replace the proxy session">Replace proxy</button>` : ''}
              <button class="btn btn-secondary btn-sm" onclick="openDeployModalForProvider('${acc.provider}', ${acc.id})">🚀 Deploy</button>
              <button class="btn btn-danger btn-sm" onclick="deleteAccount(${acc.id}, '${escapeHtml(acc.label)}')">🗑️</button>
            </div>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

// ==================== TAB: PROXY POOL & ROUTES ====================
function renderProxyManagement() {
  const totalProviders = state.proxyProviders.length;
  let totalSessions = 0;
  for (const p of state.proxyProviders) {
    totalSessions += p.total_sessions || 0;
  }
  const accWithProxy = state.accounts.filter(a => a.has_proxy).length;

  let latencies = [];
  for (const id in state.accountBilling) {
    const lat = state.accountBilling[id]?.latency_ms;
    if (typeof lat === "number" && lat > 0) latencies.push(lat);
  }
  const avgLat = latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) + "ms" : "—";

  const elP = document.getElementById("proxy-stat-providers");
  const elS = document.getElementById("proxy-stat-sessions");
  const elA = document.getElementById("proxy-stat-accounts");
  const elL = document.getElementById("proxy-stat-latency");

  if (elP) elP.textContent = totalProviders;
  if (elS) elS.textContent = totalSessions;
  if (elA) elA.textContent = accWithProxy;
  if (elL) elL.textContent = avgLat;

  const grid = document.getElementById("proxy-providers-grid");
  if (grid) {
    if (state.proxyProviders.length === 0) {
      grid.innerHTML = `<div class="col-span-full text-secondary text-sm py-6">No rotating proxy pool providers configured. Click "+ Add Rotating Proxy Pool" above to set up automated IP rotation.</div>`;
    } else {
      grid.innerHTML = state.proxyProviders.map(p => {
        const isEnabled = !!p.enabled;
        const total = p.total_sessions || 0;
        const active = p.active_sessions || 0;
        const pct = total > 0 ? Math.round((active / total) * 100) : 0;
        const boundAccs = p.bound_accounts || [];
        const scheme = (p.template_public?.scheme || 'http').toUpperCase();
        const displayUrl = p.template_public?.display || `${p.template_public?.scheme || 'http'}://${p.template_public?.host || 'proxy'}:${p.template_public?.port || '80'}`;

        return `
          <div class="proxy-provider-card" id="proxy-provider-card-${p.id}">
            <div class="proxy-provider-header">
              <div style="min-width: 0; flex: 1;">
                <div class="flex items-center gap-2 mb-1">
                  <div class="proxy-provider-title truncate">${escapeHtml(p.label)}</div>
                  <span class="badge text-xs uppercase" style="background:rgba(99,102,241,0.2);color:#818cf8;border:1px solid rgba(99,102,241,0.35);font-size:0.7rem;padding:1px 6px;">${scheme}</span>
                </div>
                <div class="text-xs text-secondary font-mono truncate" style="max-width: 320px;" title="${escapeHtml(displayUrl)}">${escapeHtml(displayUrl)}</div>
              </div>
              <span class="badge ${isEnabled ? 'badge-status-running' : 'badge-status-off'}" style="flex-shrink: 0;">${isEnabled ? 'Active' : 'Disabled'}</span>
            </div>

            <!-- Capacity Bar -->
            <div class="proxy-capacity-container">
              <div class="flex items-center justify-between text-xs">
                <span class="text-secondary">Session Capacity</span>
                <span class="font-mono font-bold text-primary">${active} / ${total} (${pct}%)</span>
              </div>
              <div class="proxy-capacity-bar">
                <div class="proxy-capacity-fill" style="width: ${pct}%"></div>
              </div>
            </div>

            <!-- Bound Accounts Section -->
            <div class="proxy-bound-accounts-section mt-3">
              <div class="flex items-center justify-between mb-2">
                <span class="text-xs font-bold text-secondary uppercase tracking-wider">Attached Accounts (${boundAccs.length})</span>
                <button class="btn btn-secondary btn-xs" onclick="openBulkSessionsModal(${p.id})" title="Bulk import sessions to this pool">➕ Import</button>
              </div>
              <div class="proxy-bound-accounts-list">
                ${boundAccs.length > 0 ? boundAccs.map(ba => {
                  const flag = getCountryFlag(ba.country);
                  return `
                    <div class="proxy-bound-chip">
                      <div class="flex items-center gap-1.5 truncate" style="min-width: 0;">
                        <span>${flag}</span>
                        <span class="font-medium text-primary truncate">#${ba.account_id} ${escapeHtml(ba.account_label)}</span>
                      </div>
                      <div class="flex items-center gap-1" style="flex-shrink: 0;">
                        <span class="badge text-xs uppercase" style="font-size:0.68rem;padding:1px 5px;">${escapeHtml(ba.country || 'GLOBAL')}</span>
                        ${ba.session_id ? `<span class="proxy-session-tag font-mono text-xs" title="${escapeHtml(ba.session_id)}">${escapeHtml(ba.session_id.length > 10 ? ba.session_id.slice(0, 8) + '…' : ba.session_id)}</span>` : ''}
                      </div>
                    </div>
                  `;
                }).join("") : '<div class="text-xs text-muted text-center py-2">No accounts currently attached</div>'}
              </div>
            </div>

            <!-- Actions -->
            <div class="flex items-center justify-between gap-2 mt-auto pt-3 border-t border-subtle flex-wrap">
              <div class="flex items-center gap-1.5 flex-wrap">
                <button class="btn btn-primary btn-sm" onclick="openManageProxySessionsModal(${p.id})" title="View and manage individual session tokens">📋 Sessions (${total})</button>
                <button class="btn btn-secondary btn-sm" onclick="openEditProxyProviderModal(${p.id})" title="Edit pool label or format">✏️</button>
              </div>
              <div class="flex items-center gap-1.5 flex-wrap">
                <button class="btn btn-secondary btn-sm" onclick="toggleProxyProvider(${p.id}, this)">${isEnabled ? '⏸ Pause' : '▶ Resume'}</button>
                <button class="btn btn-danger btn-sm" onclick="deleteProxyProvider(${p.id}, '${escapeHtml(p.label)}')">🗑️</button>
              </div>
            </div>
          </div>
        `;
      }).join("");
    }
  }

  const tbody = document.getElementById("account-proxies-tbody");
  if (tbody) {
    if (state.accounts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-secondary">No cloud accounts available.</td></tr>`;
    } else {
      tbody.innerHTML = state.accounts.map(acc => {
        const p = PROVIDERS[acc.provider] || { name: acc.provider };
        const b = state.accountBilling[acc.id];
        const latPill = b && b.latency_ms !== undefined ? (
          b.latency_ms < 200 ? `<span class="latency-tag fast">⚡ ${b.latency_ms}ms OK</span>` :
          b.latency_ms < 500 ? `<span class="latency-tag medium">⚡ ${b.latency_ms}ms High</span>` :
          `<span class="latency-tag slow">⚡ ${b.latency_ms}ms Slow</span>`
        ) : `<span class="latency-tag muted">Not Verified</span>`;

        return `
          <tr>
            <td>
              <div class="font-bold text-primary">${escapeHtml(acc.label)}</div>
              <div class="text-xs text-muted font-mono">Account #${acc.id}</div>
            </td>
            <td>
              <span class="badge badge-${acc.provider}">${p.name}</span>
            </td>
            <td>
              ${acc.has_proxy ? `
                <code class="font-mono text-xs text-primary">${escapeHtml(acc.proxy_masked || 'Configured')}</code>
              ` : `
                <span class="text-muted text-xs">Direct Server Egress</span>
              `}
            </td>
            <td>
              <span class="badge text-xs uppercase">${escapeHtml(acc.proxy_family || 'default')}</span>
            </td>
            <td>${latPill}</td>
            <td class="text-right">
              <div class="flex items-center justify-end gap-1">
                <button class="btn btn-secondary btn-sm" id="btn-test-proxy-${acc.id}" onclick="testSingleAccountProxy(${acc.id}, this)" title="Check proxy connectivity & latency">🔍 Check</button>
                <button class="btn btn-secondary btn-sm" onclick="openEditProxyModal(${acc.id})" title="Configure Proxy">⚙️ Proxy</button>
              </div>
            </td>
          </tr>
        `;
      }).join("");
    }
  }
}

// Modal: Edit Account Proxy with 3 modes (Rotating Pool, Custom, Direct)
function openEditProxyModal(accId) {
  const acc = state.accounts.find(a => a.id === accId);
  if (!acc) return;

  const idInput = document.getElementById("edit-proxy-account-id");
  const labelEl = document.getElementById("edit-proxy-account-label");
  const regEl = document.getElementById("edit-proxy-account-current-region");

  if (idInput) idInput.value = acc.id;
  if (labelEl) labelEl.textContent = `${acc.label} (${PROVIDERS[acc.provider]?.name || acc.provider})`;

  const reg = formatRegion(acc.region);
  if (regEl) regEl.textContent = `${reg.flag} ${reg.code || 'Auto'}`;

  // Populate rotating pool provider dropdown
  const provSelect = document.getElementById("pool-assign-provider");
  if (provSelect) {
    provSelect.innerHTML = state.proxyProviders.map(p =>
      `<option value="${p.id}">${escapeHtml(p.label)} (${p.active_sessions || p.total_sessions || 0} sessions)</option>`
    ).join("");
    if (state.proxyProviders.length === 0) {
      provSelect.innerHTML = `<option value="">No rotating proxy providers configured</option>`;
    }
  }

  // Pre-select country dropdown with account's saved region if valid
  const ctrySelect = document.getElementById("pool-assign-country");
  if (ctrySelect && acc.region) {
    ctrySelect.value = acc.region.toUpperCase();
  }

  // Custom proxy values
  const customInput = document.getElementById("custom-proxy-input");
  if (customInput) customInput.value = acc.has_proxy && !acc.binding ? (acc.proxy || "") : "";
  const customFam = document.getElementById("custom-proxy-family");
  if (customFam) customFam.value = acc.proxy_family || "default";
  const customReg = document.getElementById("custom-proxy-region");
  if (customReg) customReg.value = acc.region || "";

  // Reset availability text
  const availStatus = document.getElementById("pool-avail-status");
  if (availStatus) availStatus.textContent = "Ready to query session availability.";

  // Mode selection
  if (acc.binding) {
    switchProxyMode("pool");
    if (provSelect && acc.binding.provider_id) provSelect.value = acc.binding.provider_id;
    if (ctrySelect && acc.binding.country) ctrySelect.value = acc.binding.country;
  } else if (acc.has_proxy) {
    switchProxyMode("custom");
  } else {
    switchProxyMode(state.proxyProviders.length > 0 ? "pool" : "custom");
  }

  openModal("modal-edit-proxy");
}

function switchProxyMode(mode) {
  const pPool = document.getElementById("form-proxy-pool-assign");
  const pCustom = document.getElementById("form-proxy-custom-assign");
  const pDirect = document.getElementById("proxy-direct-panel");

  const btnPool = document.getElementById("tab-btn-mode-pool");
  const btnCustom = document.getElementById("tab-btn-mode-custom");
  const btnDirect = document.getElementById("tab-btn-mode-direct");

  if (btnPool) btnPool.classList.toggle("active", mode === "pool");
  if (btnCustom) btnCustom.classList.toggle("active", mode === "custom");
  if (btnDirect) btnDirect.classList.toggle("active", mode === "direct");

  if (pPool) pPool.style.display = mode === "pool" ? "block" : "none";
  if (pCustom) pCustom.style.display = mode === "custom" ? "block" : "none";
  if (pDirect) pDirect.style.display = mode === "direct" ? "block" : "none";
}

function openEditRegionModal(accId) {
  const acc = state.accounts.find(a => a.id === accId);
  if (!acc) return;
  const idInput = document.getElementById("edit-region-account-id");
  const regSel = document.getElementById("edit-region-select");
  if (idInput) idInput.value = acc.id;
  if (regSel && acc.region) {
    regSel.value = acc.region.toUpperCase();
  }
  openModal("modal-edit-region");
}

function openLinodePromoModal(accId) {
  const acc = state.accounts.find(a => a.id === Number(accId));
  if (!acc) return;
  const idInput = document.getElementById("linode-promo-acc-id");
  const labelEl = document.getElementById("linode-promo-acc-label");
  const badgeEl = document.getElementById("linode-promo-acc-id-badge");
  const codeInput = document.getElementById("linode-promo-code-input");
  const resEl = document.getElementById("linode-promo-result");

  if (idInput) idInput.value = acc.id;
  if (labelEl) labelEl.textContent = acc.label;
  if (badgeEl) badgeEl.textContent = `#${acc.id}`;
  if (codeInput) codeInput.value = "";
  if (resEl) {
    resEl.className = "hidden";
    resEl.innerHTML = "";
  }
  openModal("modal-linode-promo");
  setTimeout(() => codeInput?.focus(), 100);
}

async function testSingleAccountProxy(accId, btnEl = null) {
  const btn = btnEl || document.getElementById(`btn-test-proxy-${accId}`);
  showToast(`Testing proxy for account #${accId}...`, "info");
  await runWithButtonLoading(btn, async () => {
    try {
      let res = await api("test_account", { account_id: accId }, { retryMode: "read" });
      const account = state.accounts.find(item => String(item.id) === String(accId));
      if (res.status === "error" && account && account.has_proxy && window.CloudbotSync.proxyFailure(res.error)) {
        const recovery = await recoverFailedProxy(syncManager.snapshot().generation, account, res.error);
        if (recovery.status === "recovered" && recovery.result) res = recovery.result;
      }
      state.accountBilling[accId] = {
        status: res.status,
        info: res.info,
        identity: res.identity,
        latency_ms: res.latency_ms,
        error: res.error,
        lastChecked: new Date()
      };
      state.accountErrors = state.accountErrors || {};
      if (res.status === "error") {
        state.accountErrors[accId] = res.error;
        state.accountErrors[String(accId)] = res.error;
        const isProxy = window.CloudbotSync.proxyFailure(res.error || "");
        showToast(isProxy ? `⚠️ Proxy failed for account #${accId}: ${res.error}` : `Connection error for account #${accId}: ${res.error}`, "error");
      } else {
        delete state.accountErrors[accId];
        delete state.accountErrors[String(accId)];
        showToast(`Proxy verified! Latency: ${res.latency_ms}ms`, "success");
      }
      renderAllViews();
    } catch (err) {
      state.accountErrors = state.accountErrors || {};
      state.accountErrors[accId] = err.message;
      state.accountErrors[String(accId)] = err.message;
      renderAllViews();
      showToast(`Test error: ${err.message}`, "error");
    }
  }, "Testing...");
}

async function checkAllAccountProxies(btnEl = null) {
  const btn = btnEl || document.getElementById("btn-check-all-proxies");
  const accsWithProxy = state.accounts.filter(a => a.has_proxy);
  if (accsWithProxy.length === 0) {
    showToast("No accounts currently have a proxy configured.", "info");
    return;
  }
  showToast(`Checking ${accsWithProxy.length} account proxies...`, "info");
  await runWithButtonLoading(btn, async () => {
    let successCount = 0;
    let failCount = 0;
    for (let i = 0; i < accsWithProxy.length; i++) {
      const acc = accsWithProxy[i];
      try {
        let res = await api("test_account", { account_id: acc.id }, { retryMode: "read" });
        if (res.status === "error" && acc.has_proxy && window.CloudbotSync.proxyFailure(res.error)) {
          const recovery = await recoverFailedProxy(syncManager.snapshot().generation, acc, res.error);
          if (recovery.status === "recovered" && recovery.result) res = recovery.result;
        }
        state.accountBilling[acc.id] = {
          status: res.status,
          info: res.info,
          identity: res.identity,
          latency_ms: res.latency_ms,
          error: res.error,
          lastChecked: new Date()
        };
        state.accountErrors = state.accountErrors || {};
        if (res.status === "error") {
          state.accountErrors[acc.id] = res.error;
          state.accountErrors[String(acc.id)] = res.error;
          failCount++;
        } else {
          delete state.accountErrors[acc.id];
          delete state.accountErrors[String(acc.id)];
          successCount++;
        }
      } catch (err) {
        state.accountErrors = state.accountErrors || {};
        state.accountErrors[acc.id] = err.message;
        state.accountErrors[String(acc.id)] = err.message;
        failCount++;
      }
    }
    renderAllViews();
    showToast(`Checked ${accsWithProxy.length} proxies: ${successCount} OK, ${failCount} failed.`, failCount > 0 ? "warning" : "success");
  }, "Checking All...");
}

// ==================== PROXY PROTOCOL & CREATION MODES ====================
let activeProxyCreationMode = 'builder';

function switchProxyCreationMode(mode) {
  activeProxyCreationMode = mode;
  document.querySelectorAll(".proxy-mode-tab").forEach(tab => {
    tab.classList.toggle("active", tab.getAttribute("data-proxy-mode") === mode);
  });
  const bPane = document.getElementById("proxy-mode-builder-pane");
  const uPane = document.getElementById("proxy-mode-url-pane");
  const sPane = document.getElementById("proxy-mode-sample-pane");
  if (bPane) bPane.style.display = mode === 'builder' ? 'block' : 'none';
  if (uPane) uPane.style.display = mode === 'url' ? 'block' : 'none';
  if (sPane) sPane.style.display = mode === 'sample' ? 'block' : 'none';
  updateBuilderTemplatePreview();
}

function selectProxyScheme(scheme) {
  const schemeInput = document.getElementById("builder-proxy-scheme");
  if (schemeInput) schemeInput.value = scheme;
  document.querySelectorAll("#builder-proxy-type-group .proxy-type-pill").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-scheme") === scheme);
  });
  updateBuilderTemplatePreview();
}

function setTestProxyScheme(scheme) {
  const schemeInput = document.getElementById("test-proxy-scheme");
  if (schemeInput) schemeInput.value = scheme;
  document.querySelectorAll("#test-proxy-type-group .proxy-type-pill").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-scheme") === scheme);
  });
}

function insertTokenToUsername(token) {
  const userInp = document.getElementById("builder-proxy-user");
  if (!userInp) return;
  const start = userInp.selectionStart || userInp.value.length;
  const end = userInp.selectionEnd || userInp.value.length;
  userInp.value = userInp.value.substring(0, start) + token + userInp.value.substring(end);
  userInp.focus();
  userInp.selectionStart = userInp.selectionEnd = start + token.length;
  updateBuilderTemplatePreview();
}

function updateBuilderTemplatePreview() {
  const prevEl = document.getElementById("proxy-template-preview");
  if (!prevEl) return;
  if (activeProxyCreationMode === 'url') {
    const rawVal = document.getElementById("proxy-provider-template")?.value.trim();
    prevEl.textContent = rawVal || "Enter proxy template above...";
    return;
  }
  const scheme = document.getElementById("builder-proxy-scheme")?.value || "http";
  const host = document.getElementById("builder-proxy-host")?.value.trim() || "proxy.example.com";
  const port = document.getElementById("builder-proxy-port")?.value.trim() || "8080";
  const user = document.getElementById("builder-proxy-user")?.value.trim() || "user-{country}-{session}";
  const pass = document.getElementById("builder-proxy-pass")?.value.trim();
  const passPart = pass ? "••••••" : "pass";
  prevEl.textContent = `${scheme}://${user}:${passPart}@${host}:${port}`;
}

async function parseSampleProxyLines() {
  const raw = document.getElementById("proxy-sample-lines-input")?.value.trim();
  const statusEl = document.getElementById("proxy-sample-status");
  if (!raw) {
    if (statusEl) statusEl.textContent = "Please paste sample lines first.";
    return;
  }
  if (statusEl) statusEl.textContent = "Analyzing patterns...";
  try {
    const parsed = await api("parse_proxy_sessions", { text: raw });
    const sids = parsed.session_ids || [];
    if (sids.length > 0) {
      document.getElementById("proxy-provider-sessions").value = sids.slice(0, 50).join(",");
      if (statusEl) statusEl.textContent = `✅ Detected ${sids.length} session tokens!`;
    } else {
      if (statusEl) statusEl.textContent = "Could not extract session IDs automatically; enter manually.";
    }
  } catch (err) {
    if (statusEl) statusEl.textContent = `Error: ${err.message}`;
  }
}

function openAddProxyProviderModal() {
  document.getElementById("form-add-proxy-provider")?.reset();
  switchProxyCreationMode('builder');
  selectProxyScheme('http');
  updateBuilderTemplatePreview();
  openModal("modal-add-proxy-provider");
}

// ==================== POOL SESSIONS MANAGER ====================
let currentManageSessionsProvider = null;
let currentManageSessionsList = [];

async function openManageProxySessionsModal(providerId) {
  currentManageSessionsProvider = state.proxyProviders.find(p => p.id === Number(providerId));
  const subTitle = document.getElementById("manage-sessions-subtitle");
  const pName = currentManageSessionsProvider ? currentManageSessionsProvider.label : `#${providerId}`;
  if (subTitle) subTitle.textContent = `Pool: ${pName}`;
  const tbody = document.getElementById("manage-sessions-tbody");
  if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-secondary">Loading sessions from database...</td></tr>`;
  openModal("modal-manage-proxy-sessions");

  try {
    const res = await api("proxy_sessions", { provider_id: providerId });
    currentManageSessionsList = res.sessions || [];
    const statTotal = document.getElementById("stat-mng-total");
    const statActive = document.getElementById("stat-mng-active");
    const statBound = document.getElementById("stat-mng-bound");
    const statScheme = document.getElementById("stat-mng-scheme");
    if (statTotal) statTotal.textContent = res.total_count ?? currentManageSessionsList.length;
    if (statActive) statActive.textContent = res.active_count ?? currentManageSessionsList.filter(s => s.enabled).length;
    if (statBound) statBound.textContent = res.bound_count ?? currentManageSessionsList.filter(s => s.is_bound).length;
    if (statScheme && currentManageSessionsProvider) {
      statScheme.textContent = (currentManageSessionsProvider.template_public?.scheme || "HTTP").toUpperCase();
    }
    renderManageSessionsTable(currentManageSessionsList);
  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-danger">${escapeHtml(err.message)}</td></tr>`;
  }
}

function renderManageSessionsTable(sessions) {
  const tbody = document.getElementById("manage-sessions-tbody");
  if (!tbody) return;
  if (!sessions || sessions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-muted">No session tokens found in this pool. Add one above!</td></tr>`;
    return;
  }
  tbody.innerHTML = sessions.map((s, idx) => {
    const isAct = !!s.enabled;
    const isBnd = !!s.is_bound;
    const bound = s.bound_to;
    const boundHtml = isBnd && bound ? `
      <div class="flex items-center gap-1.5">
        <span>${getCountryFlag(bound.country)}</span>
        <span class="font-medium text-primary text-xs">#${bound.account_id} ${escapeHtml(bound.account_label || '')}</span>
      </div>
    ` : `<span class="text-xs text-muted">Unallocated / Free</span>`;

    return `
      <tr id="session-row-${s.id || idx}">
        <td class="font-mono text-xs text-secondary">${idx + 1}</td>
        <td>
          <span class="ip-copyable" onclick="copyText('${escapeHtml(s.session_id)}')">
            <code class="font-mono text-xs font-bold text-primary">${escapeHtml(s.session_id)}</code>
            <span class="text-xs text-muted">📋</span>
          </span>
        </td>
        <td>
          <span class="badge ${isAct ? 'badge-status-running' : 'badge-status-off'}">${isAct ? 'Active' : 'Disabled'}</span>
        </td>
        <td>${boundHtml}</td>
        <td class="text-right">
          <div class="flex items-center justify-end gap-1">
            <button class="btn-icon-xs ${isAct ? 'btn-icon-warning' : 'btn-icon-success'}" onclick="toggleProxySession(${s.provider_id}, '${escapeHtml(s.session_id)}')" title="${isAct ? 'Disable Session' : 'Enable Session'}">
              ${isAct ? '⏸' : '▶'}
            </button>
            <button class="btn-icon-xs btn-icon-danger" onclick="deleteProxySession(${s.provider_id}, '${escapeHtml(s.session_id)}')" title="Delete Session">
              🗑️
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

function filterPoolSessionsList() {
  const query = (document.getElementById("search-pool-sessions-input")?.value || "").toLowerCase().trim();
  if (!query) {
    renderManageSessionsTable(currentManageSessionsList);
    return;
  }
  const filtered = currentManageSessionsList.filter(s => {
    return s.session_id.toLowerCase().includes(query) ||
           (s.bound_to && (s.bound_to.account_label || '').toLowerCase().includes(query)) ||
           (s.bound_to && (s.bound_to.country || '').toLowerCase().includes(query));
  });
  renderManageSessionsTable(filtered);
}

async function submitQuickAddSession() {
  if (!currentManageSessionsProvider) return;
  const inputEl = document.getElementById("input-quick-add-session");
  const raw = inputEl?.value.trim();
  if (!raw) {
    showToast("Please enter a session ID or range e.g. 51-100", "error");
    return;
  }
  const btn = document.getElementById("btn-quick-add-session");
  await runWithButtonLoading(btn, async () => {
    try {
      const res = await api("add_proxy_sessions", {
        provider_id: currentManageSessionsProvider.id,
        raw_text: raw
      });
      showToast(`Added ${res.added} session(s) successfully!`, "success");
      if (inputEl) inputEl.value = "";
      openManageProxySessionsModal(currentManageSessionsProvider.id);
      const provRes = await api("proxy_providers");
      state.proxyProviders = provRes.providers || [];
      renderProxyManagement();
    } catch (err) {
      showToast(`Error: ${err.message}`, "error");
    }
  }, "Adding...");
}

async function toggleProxySession(pid, sid) {
  try {
    await api("toggle_proxy_session", { provider_id: pid, session_id: sid });
    showToast(`Session ${sid} updated!`, "success");
    openManageProxySessionsModal(pid);
    const provRes = await api("proxy_providers");
    state.proxyProviders = provRes.providers || [];
    renderProxyManagement();
  } catch (err) {
    showToast(`Failed: ${err.message}`, "error");
  }
}

async function deleteProxySession(pid, sid) {
  confirmAction(`Delete session "${sid}" from this pool?`, "DELETE", async () => {
    try {
      await api("delete_proxy_session", { provider_id: pid, session_id: sid });
      showToast(`Session ${sid} deleted!`, "success");
      openManageProxySessionsModal(pid);
      const provRes = await api("proxy_providers");
      state.proxyProviders = provRes.providers || [];
      renderProxyManagement();
    } catch (err) {
      showToast(`Failed: ${err.message}`, "error");
    }
  });
}

function openBulkSessionsModalFromManager() {
  if (currentManageSessionsProvider) {
    openBulkSessionsModal(currentManageSessionsProvider.id);
  } else {
    openBulkSessionsModal();
  }
}

function openEditProxyProviderModal(providerId) {
  const p = state.proxyProviders.find(x => x.id === Number(providerId));
  if (!p) return;
  document.getElementById("edit-proxy-provider-id").value = p.id;
  document.getElementById("edit-proxy-provider-label").value = p.label || "";
  document.getElementById("edit-proxy-provider-template").value = "";
  openModal("modal-edit-proxy-provider");
}

async function toggleProxyProvider(pid, btnEl = null) {
  await runWithButtonLoading(btnEl, async () => {
    try {
      await api("toggle_proxy_provider", { provider_id: pid });
      showToast("Proxy pool status toggled", "success");
      const res = await api("proxy_providers");
      state.proxyProviders = res.providers || [];
      renderProxyManagement();
    } catch (err) {
      showToast("Failed to toggle provider: " + err.message, "error");
    }
  });
}

async function deleteProxyProvider(pid, label) {
  confirmAction(`Delete proxy provider "${label}"? Associated rotating sessions will be removed.`, "DELETE_PROXY_PROVIDER", async () => {
    try {
      await api("delete_proxy_provider", { provider_id: pid, confirm: "DELETE_PROXY_PROVIDER" });
      showToast("Proxy provider removed", "success");
      const res = await api("proxy_providers");
      state.proxyProviders = res.providers || [];
      renderProxyManagement();
    } catch (err) {
      showToast("Failed to delete provider: " + err.message, "error");
    }
  });
}

function openTestProxyModal() {
  document.getElementById("form-quick-test-proxy")?.reset();
  const input = document.getElementById("test-proxy-string-input");
  if (input) {
    input.value = "";
    input.removeAttribute("data-account-id");
  }
  setTestProxyScheme('auto');
  const badge = document.getElementById("test-proxy-status-badge");
  const details = document.getElementById("test-proxy-details");
  if (badge) { badge.className = "badge"; badge.textContent = "Ready"; }
  if (details) details.textContent = 'Click "Check Proxy" to test egress IP and latency.';

  const accSelect = document.getElementById("test-proxy-account-select");
  if (accSelect) {
    accSelect.innerHTML = `<option value="">— Enter Custom Proxy Below —</option>` +
      state.accounts.map(a => `<option value="${a.id}">#${a.id} ${escapeHtml(a.label)} (${(a.provider || '').toUpperCase()}) - ${a.has_proxy ? (a.proxy_masked || 'Configured') : 'Direct'}</option>`).join("");
  }

  openModal("modal-test-proxy");
}

function onSelectTestProxyAccount(accId) {
  const input = document.getElementById("test-proxy-string-input");
  if (!input) return;
  if (!accId) {
    input.value = "";
    input.removeAttribute("data-account-id");
    return;
  }
  const acc = state.accounts.find(a => a.id === parseInt(accId, 10));
  if (!acc) return;
  if (!acc.has_proxy) {
    showToast(`Account #${acc.id} uses Direct Server Egress (no proxy).`, "info");
    input.value = "";
    input.removeAttribute("data-account-id");
    return;
  }
  input.value = `Account #${acc.id}: ${acc.label} (${acc.proxy_masked || 'Proxy Configured'})`;
  input.setAttribute("data-account-id", String(acc.id));
}

// ==================== PROVIDER HUBS (ACCOUNTS FIRST -> CLICK TO DRILL DOWN) ====================
function selectProviderAccount(provider, accountId) {
  state.providerSelectedAccount[provider] = accountId ? Number(accountId) : null;
  if (provider === "hetzner") renderHetznerHub();
  else if (provider === "vultr") renderVultrHub();
  else if (provider === "linode") renderLinodeHub();
}

function setAccountSubTab(provider, tab) {
  state.providerAccountSubTab = state.providerAccountSubTab || {};
  state.providerAccountSubTab[provider] = tab;
  renderProviderHubView(provider);
}
window.setAccountSubTab = setAccountSubTab;

function formatReverseDnsText(dnsPtr) {
  if (!dnsPtr) return "";
  if (typeof dnsPtr === "string") return dnsPtr;
  if (Array.isArray(dnsPtr)) {
    return dnsPtr.map(d => (typeof d === "string" ? d : (d && d.dns_ptr ? d.dns_ptr : ""))).filter(Boolean).join(", ");
  }
  if (typeof dnsPtr === "object" && dnsPtr.dns_ptr) return String(dnsPtr.dns_ptr);
  return "";
}

function navigateToAccount(provider, accountId) {
  state.providerSelectedAccount[provider] = accountId ? Number(accountId) : null;
  switchTab(`tab-${provider}`, true);
}

function renderProviderHubView(provider) {
  state.providerAccountSubTab = state.providerAccountSubTab || {};
  if (!state.providerAccountSubTab[provider]) {
    state.providerAccountSubTab[provider] = "instances";
  }
  let subTab = state.providerAccountSubTab[provider] || "instances";
  if (subTab === "ips" && provider !== "hetzner" && provider !== "vultr") {
    subTab = "instances";
    state.providerAccountSubTab[provider] = "instances";
  }

  const p = PROVIDERS[provider] || { name: provider, logo: "/ui/assets/cloud.svg", badgeClass: "badge-hetzner" };
  const accs = state.accounts.filter(a => a.provider === provider);
  const accsView = document.getElementById(`${provider}-accounts-view`);
  const serversView = document.getElementById(`${provider}-servers-view`);
  const accsGrid = document.getElementById(`${provider}-accounts-grid`);

  if (!accsView || !serversView || !accsGrid) return;

  // Render provider summary stats ribbon if container exists
  const statsEl = document.getElementById(`${provider}-summary-stats`);
  if (statsEl) {
    const srvs = state.servers.filter(s => s.provider === provider);
    let badgesHtml = `<span class="badge ${p.badgeClass}">${accs.length} Accounts</span> <span class="badge badge-secondary">${srvs.length} Instances</span>`;

    if (provider === "linode") {
      let totalCredit = 0;
      let totalUnbilled = 0;
      for (const a of accs) {
        const info = state.accountBilling[a.id]?.info;
        if (info) {
          totalCredit += Number(info.credit || 0);
          totalUnbilled += Number(info.pending_charges || 0);
        }
      }
      if (totalCredit > 0) {
        badgesHtml += ` <span class="badge badge-status-running">💳 Total Credit: $${totalCredit.toFixed(2)}</span>`;
      }
      if (totalUnbilled > 0) {
        badgesHtml += ` <span class="badge badge-secondary">⏳ Unbilled: $${totalUnbilled.toFixed(2)}</span>`;
      }
    } else if (provider === "vultr") {
      let totalBal = 0;
      let totalPending = 0;
      for (const a of accs) {
        const info = state.accountBilling[a.id]?.info;
        if (info) {
          totalBal += Number(info.balance || 0);
          totalPending += Number(info.pending_charges || 0);
        }
      }
      if (totalBal < 0) {
        badgesHtml += ` <span class="badge badge-status-running">💳 Net Credit: -$${Math.abs(totalBal).toFixed(2)}</span>`;
      } else if (totalBal > 0) {
        badgesHtml += ` <span class="badge badge-danger">💳 Total Owed: $${totalBal.toFixed(2)}</span>`;
      }
      if (totalPending > 0) {
        badgesHtml += ` <span class="badge badge-secondary">⏳ Total Pending: $${totalPending.toFixed(2)}</span>`;
      }
    } else if (provider === "hetzner") {
      let totalMonthly = 0;
      for (const a of accs) {
        const info = state.accountBilling[a.id]?.info;
        if (info) totalMonthly += Number(info.monthly_runrate || 0);
      }
      if (totalMonthly > 0) {
        badgesHtml += ` <span class="badge badge-hetzner">💶 Est. Cost: €${totalMonthly.toFixed(2)}/mo</span>`;
      }
    }
    badgesHtml += ` <button class="btn btn-secondary btn-xs" onclick="refreshAllBillingDetails()" title="Refresh live balances">🔄 Refresh</button>`;
    statsEl.innerHTML = badgesHtml;
  }

  const selectedAccId = state.providerSelectedAccount[provider];

  if (!selectedAccId) {
    // 1. Show Accounts View Only (No server tables stacked underneath!)
    accsView.style.display = "block";
    serversView.style.display = "none";

    if (accs.length === 0) {
      accsGrid.innerHTML = `
        <div class="col-span-full text-center py-12 text-secondary">
          No ${p.name} accounts configured yet.<br>
          <button class="btn btn-primary btn-sm mt-3" onclick="openAddAccountModalFor('${provider}')">+ Add ${p.name} Account</button>
        </div>
      `;
      return;
    }

    accsGrid.innerHTML = accs.map(acc => {
      const accServers = state.servers.filter(s => s.account_id === acc.id);
      const count = accServers.length;
      const fail = getAccountFailureStatus(acc.id);
      const proxyLabel = formatAccountProxyLabel(acc);
      const b = state.accountBilling[acc.id];
      const reg = formatRegion(acc.region);
      const bDetails = formatAccountBillingDetails(acc, b, fail);

      return `
        <div class="account-card account-card-clickable ${fail ? 'border-danger' : ''}" onclick="selectProviderAccount('${provider}', ${acc.id})">
          <div class="account-card-header">
            <div class="flex items-center gap-2" style="min-width: 0; overflow: hidden;">
              <img src="${p.logo}" width="20" height="20">
              <span class="account-card-title">${escapeHtml(acc.label)}</span>
            </div>
            <div class="flex items-center gap-1.5 flex-shrink-0">
              ${fail ? `<span class="badge badge-danger">⚠️ Proxy Failed</span>` : `
                <span class="badge ${p.badgeClass}">${count} instances</span>
                ${bDetails.badge || ''}
              `}
            </div>
          </div>
          <table class="account-card-info-table">
            <tr><td>Account ID:</td><td class="font-mono">#${acc.id}</td></tr>
            <tr><td>Region:</td><td>${reg.flag} ${escapeHtml(reg.name || reg.code || 'Not Specified')}</td></tr>
            <tr><td>Proxy:</td><td class="font-mono text-xs">${escapeHtml(proxyLabel)}</td></tr>
            <tr><td>Credit / Balance:</td><td>${bDetails.balanceDisplay}</td></tr>
            ${bDetails.usageDisplay ? `<tr><td>Usage / Pending:</td><td>${bDetails.usageDisplay}</td></tr>` : ''}
            <tr><td>Status:</td><td>${fail ? `<span class="text-danger font-bold text-xs"><span class="status-dot offline"></span> ${escapeHtml(fail.title)}</span>` : `<span class="text-success text-xs"><span class="status-dot online"></span> Connected</span>`}</td></tr>
            ${b && b.latency_ms !== undefined ? `<tr><td>Latency:</td><td class="font-mono text-xs text-secondary">⚡ ${b.latency_ms}ms</td></tr>` : ''}
            ${fail ? `<tr><td>Details:</td><td class="text-danger font-mono text-xs" style="word-break: break-all;">${escapeHtml(fail.error.length > 70 ? fail.error.substring(0, 68) + '…' : fail.error)}</td></tr>` : ''}
          </table>
          <div class="account-card-footer" onclick="event.stopPropagation()">
            <button class="btn btn-primary btn-sm w-full account-card-view-btn" onclick="selectProviderAccount('${provider}', ${acc.id})">
              🖥️ View Servers (${count}) ➔
            </button>
            <div class="account-card-actions">
              <button class="btn btn-secondary btn-sm flex-1" onclick="openDeployModalForAccount(${acc.id}, '${provider}')" title="Deploy instance">+ Deploy</button>
              <button class="btn btn-secondary btn-sm flex-1" onclick="openEditProxyModal(${acc.id})" title="Configure proxy">⚙️ Proxy</button>
              <button class="btn btn-secondary btn-sm btn-icon-sm" id="btn-check-status-${acc.id}" onclick="checkAccountStatus(${acc.id}, this)" title="Check status">🔄</button>
              <button class="btn btn-danger btn-sm btn-icon-sm" onclick="deleteAccount(${acc.id}, '${escapeHtml(acc.label)}')" title="Delete account">🗑️</button>
            </div>
          </div>
        </div>
      `;
    }).join("");
  } else {
    // 2. Show Account Instances Drilldown View (When an account is clicked!)
    const acc = accs.find(a => a.id === selectedAccId);
    if (!acc) {
      state.providerSelectedAccount[provider] = null;
      renderProviderHubView(provider);
      return;
    }

    accsView.style.display = "none";
    serversView.style.display = "block";

    const accServers = state.servers.filter(s => s.account_id === acc.id);
    const fail = getAccountFailureStatus(acc.id);
    const proxyLabel = formatAccountProxyLabel(acc);
    const b = state.accountBilling[acc.id];
    const reg = formatRegion(acc.region);
    const bDetails = formatAccountBillingDetails(acc, b, fail);
    const showFips = provider === "hetzner" || provider === "vultr";

    const accFips = showFips ? state.floatingIps.filter(f => f.account_id === acc.id) : [];
    const accPrimaryIps = (provider === "hetzner") ? state.primaryIps.filter(p => p.account_id === acc.id) : [];

    const allAccountIps = [];
    accFips.forEach(f => {
      allAccountIps.push({
        id: f.id,
        ip: f.ip || f.subnet || f.ip_address,
        type: f.type || 'ipv4',
        kind: 'floating',
        kindLabel: 'Floating IP',
        serverId: f.server_id || null,
        location: f.location || f.region || '—',
        name: f.name || f.label || '',
        dns_ptr: f.dns_ptr || f.reverse || '',
        description: f.description || f.name || '',
        raw: f
      });
    });
    accPrimaryIps.forEach(p => {
      allAccountIps.push({
        id: p.id,
        ip: p.ip,
        type: p.type || 'ipv4',
        kind: 'primary',
        kindLabel: 'Primary IP',
        serverId: p.assignee_id || null,
        location: p.datacenter || p.location || '—',
        name: p.name || '',
        dns_ptr: p.dns_ptr || '',
        description: p.auto_delete ? 'Auto-delete with server' : 'Retained',
        raw: p
      });
    });

    const totalAccountIps = allAccountIps.length;
    const totalIps = totalAccountIps;
    const attachedCount = allAccountIps.filter(x => x.serverId).length;
    const unassignedCount = totalAccountIps - attachedCount;

    let html = `
      <div class="account-drilldown-header">
        <div class="flex items-center gap-3">
          <button class="btn btn-secondary btn-sm" onclick="selectProviderAccount('${provider}', null)">
            ← All ${p.name} Accounts
          </button>
          <div style="width: 1px; height: 24px; background: var(--border-subtle);"></div>
          <div class="flex items-center gap-2">
            <img src="${p.logo}" width="22" height="22">
            <h2 class="text-lg font-bold text-primary">${escapeHtml(acc.label)}</h2>
            <span class="badge ${p.badgeClass}">ID: ${acc.id}</span>
            ${fail ? '<span class="badge badge-danger">⚠️ Proxy Failed</span>' : '<span class="badge badge-status-running"><span class="w-1.5 h-1.5 rounded-full bg-success"></span> Connected</span>'}
            ${bDetails.badge ? bDetails.badge : ''}
          </div>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          ${accs.length > 1 ? `
            <div class="flex items-center gap-1.5 text-xs text-secondary">
              <span>Switch Account:</span>
              <select class="select-input text-xs" onchange="selectProviderAccount('${provider}', this.value)" style="width: auto; padding: 4px 8px;">
                ${accs.map(a => `<option value="${a.id}" ${a.id === acc.id ? 'selected' : ''}>${escapeHtml(a.label)} (${state.servers.filter(s => s.account_id === a.id).length})</option>`).join("")}
              </select>
            </div>
          ` : ''}
          <button class="btn btn-secondary btn-sm" onclick="openEditProxyModal(${acc.id})" title="Configure proxy">⚙️ Proxy</button>
          ${provider === "linode" ? `<button class="btn btn-secondary btn-sm" onclick="openLinodePromoModal(${acc.id})" title="Apply Linode Promo Code">🎟 Apply Promo</button>` : ''}
          <button class="btn btn-secondary btn-sm" id="btn-check-status-drilldown-${acc.id}" onclick="checkAccountStatus(${acc.id}, this)" title="Refresh account details">🔄</button>
          <button class="btn btn-primary btn-sm" onclick="openDeployModalForAccount(${acc.id}, '${provider}')">🚀 + Deploy Instance</button>
        </div>
      </div>

      <div class="account-drilldown-meta">
        <div class="flex items-center gap-1.5">
          <span class="text-tertiary">Region:</span>
          <strong>${reg.flag} ${escapeHtml(reg.name || reg.code || 'Not Specified')}</strong>
        </div>
        <span>•</span>
        <div class="flex items-center gap-1.5">
          <span class="text-tertiary">Proxy:</span>
          <span class="font-mono text-xs">${escapeHtml(proxyLabel)}</span>
        </div>
        <span>•</span>
        <div class="flex items-center gap-1.5">
          <span class="text-tertiary">Instances:</span>
          <strong>${accServers.length} Total</strong>
        </div>
        <span>•</span>
        <div class="flex items-center gap-1.5">
          <span class="text-tertiary">Credit / Balance:</span>
          <strong>${bDetails.balanceDisplay}</strong>
        </div>
        ${bDetails.usageDisplay ? `
          <span>•</span>
          <div class="flex items-center gap-1.5">
            <span class="text-tertiary">Usage / Pending:</span>
            <strong>${bDetails.usageDisplay}</strong>
          </div>
        ` : ''}
        ${b && b.latency_ms !== undefined ? `
          <span>•</span>
          <div class="flex items-center gap-1.5">
            <span class="text-tertiary">Latency:</span>
            <span class="text-success font-bold font-mono">⚡ ${b.latency_ms}ms</span>
          </div>
        ` : ''}
      </div>

      <div class="account-subtabs-nav">
        <button type="button" class="account-subtab-btn ${subTab === 'instances' ? 'active' : ''}" onclick="setAccountSubTab('${provider}', 'instances')">
          🖥️ Compute Instances (${accServers.length})
        </button>
        ${(provider === 'hetzner' || provider === 'vultr') ? `
          <button type="button" class="account-subtab-btn ${subTab === 'ips' ? 'active' : ''}" onclick="setAccountSubTab('${provider}', 'ips')">
            🌐 IP Management (${totalAccountIps}) ${unassignedCount > 0 ? `<span class="badge badge-warning text-xs ml-1">${unassignedCount} Free</span>` : ''}
          </button>
        ` : ''}
      </div>
    `;

    if (fail) {
      html += `
        <div class="mb-6" style="padding: 1.25rem; background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.35); border-radius: var(--radius-md);">
          <div class="text-base font-bold text-danger mb-1">
            ⚠️ ${fail.isProxy ? 'Proxy Failed for this Account' : 'Account Connection Failed'}
          </div>
          <div class="text-xs text-secondary mb-3">
            Cloudbot could not reach ${p.name} for <strong>${escapeHtml(acc.label)}</strong> through its configured proxy.
          </div>
          <div class="text-xs font-mono text-danger mb-3 p-2 bg-black rounded" style="word-break: break-all; text-align: left;">
            ${escapeHtml(fail.error)}
          </div>
          <div class="flex items-center gap-2">
            <button class="btn btn-primary btn-sm" onclick="openEditProxyModal(${acc.id})">⚙️ Reconfigure Proxy</button>
            <button class="btn btn-secondary btn-sm" onclick="checkAccountStatus(${acc.id}, this)">🔄 Retry Connection</button>
          </div>
        </div>
      `;
    }

    if (subTab === "instances") {
      // 1. Compute Instances Tab View (ONLY instances and deploy controls)
      if (accServers.length === 0) {
        html += `
          <div class="data-table-container text-center py-12 text-secondary">
            No instances deployed under <strong>${escapeHtml(acc.label)}</strong>.<br>
            <button class="btn btn-primary btn-sm mt-3" onclick="openDeployModalForAccount(${acc.id}, '${provider}')">🚀 Deploy First Instance</button>
          </div>
        `;
      } else {
        html += `
          <!-- Bulk Actions Toolbar for Account Drilldown -->
          <div id="drilldown-bulk-bar" class="bulk-actions-toolbar" style="display: none;">
            <div class="flex items-center gap-2">
              <span class="bulk-count-badge" id="drilldown-bulk-count">0</span>
              <span class="text-sm font-medium">instances selected</span>
            </div>
            <div class="flex items-center gap-2">
              <button type="button" class="btn btn-secondary btn-sm" onclick="clearServerSelection()">Deselect All</button>
              <button type="button" class="btn btn-danger btn-sm" id="btn-drilldown-bulk-delete" onclick="deleteSelectedServers(this)">
                🗑️ Delete Selected Instances (<span id="drilldown-bulk-btn-count">0</span>)
              </button>
            </div>
          </div>

          <div class="data-table-container">
            <div class="table-responsive">
              <table class="data-table">
                <thead>
                  <tr>
                    <th style="width: 38px; text-align: center;">
                      <input type="checkbox" class="cb-select-all" onchange="toggleSelectAllInView(this, 'drilldown-servers-tbody')" title="Select all visible instances">
                    </th>
                    <th>Instance Name</th>
                    <th>Status</th>
                    <th>Location</th>
                    <th>Primary IP</th>
                    ${showFips ? '<th>Floating IP</th>' : ''}
                    <th>Plan</th>
                    <th class="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody id="drilldown-servers-tbody">
                  ${accServers.map(s => renderServerRow(s, false, showFips, true)).join("")}
                </tbody>
              </table>
            </div>
          </div>
        `;
      }
    } else if (subTab === "ips") {
      // 2. Dedicated Account IP Management View - Separate Floating and Primary IPs!
      const currentFilter = state.providerIpFilter || "all";
      let filteredFips = accFips;
      if (currentFilter === "attached") {
        filteredFips = accFips.filter(x => x.server_id);
      } else if (currentFilter === "unassigned") {
        filteredFips = accFips.filter(x => !x.server_id);
      }

      const fipsAttachedCount = accFips.filter(x => x.server_id).length;
      const fipsUnassignedCount = accFips.length - fipsAttachedCount;

      html += `
        <div class="account-ip-management-view">
          <!-- SECTION 1: Floating IPs -->
          <div class="hetzner-ip-section-card">
            <div class="flex items-center justify-between mb-4 flex-wrap gap-2">
              <div>
                <h3 class="text-base font-bold text-primary flex items-center gap-2">
                  <span>🌐 ${provider === 'hetzner' ? 'Hetzner Floating IPs' : 'Vultr Reserved & Floating IPs'}</span>
                  <span class="badge badge-secondary text-xs">${accFips.length}</span>
                </h3>
                <div class="text-xs text-secondary mt-0.5">Flexible virtual IPs that can be dynamically reassigned between instances</div>
              </div>
              <button class="btn btn-primary btn-sm" onclick="openAllocIpModal(${acc.id})">
                ⚡ + Allocate Floating IP
              </button>
            </div>

            <!-- Mini Metrics for Floating IPs -->
            <div class="account-ip-metrics-ribbon mb-4">
              <div class="account-ip-metric-card">
                <div class="account-ip-metric-header">
                  <span class="account-ip-metric-label">Floating IPs</span>
                  <span class="account-ip-metric-icon">🌐</span>
                </div>
                <div class="account-ip-metric-val">${accFips.length}</div>
                <div class="account-ip-metric-sub">Allocated in this account</div>
              </div>
              <div class="account-ip-metric-card">
                <div class="account-ip-metric-header">
                  <span class="account-ip-metric-label">Attached</span>
                  <span class="account-ip-metric-icon">⚡</span>
                </div>
                <div class="account-ip-metric-val text-success">${fipsAttachedCount}</div>
                <div class="account-ip-metric-sub">Active on instances</div>
              </div>
              <div class="account-ip-metric-card ${fipsUnassignedCount > 0 ? 'highlight-warning' : ''}">
                <div class="account-ip-metric-header">
                  <span class="account-ip-metric-label">Free / Unassigned</span>
                  <span class="account-ip-metric-icon">⚠️</span>
                </div>
                <div class="account-ip-metric-val ${fipsUnassignedCount > 0 ? 'text-warning' : 'text-secondary'}">${fipsUnassignedCount}</div>
                <div class="account-ip-metric-sub">${fipsUnassignedCount > 0 ? 'Ready to attach' : 'All IPs bound to servers'}</div>
              </div>
            </div>

            <div class="account-ip-controls-row">
              <div class="flex items-center gap-1 bg-surface p-1 rounded-md border border-subtle">
                <button type="button" class="fip-filter-btn ${currentFilter === 'all' ? 'active' : ''}" onclick="setProviderIpFilter('all', '${provider}')">
                  All (${accFips.length})
                </button>
                <button type="button" class="fip-filter-btn ${currentFilter === 'attached' ? 'active' : ''}" onclick="setProviderIpFilter('attached', '${provider}')">
                  Attached (${fipsAttachedCount})
                </button>
                <button type="button" class="fip-filter-btn ${currentFilter === 'unassigned' ? 'active' : ''}" onclick="setProviderIpFilter('unassigned', '${provider}')">
                  ⚠️ Unassigned (${fipsUnassignedCount})
                </button>
              </div>
            </div>

            <!-- Bulk Actions Toolbar for Drilldown IPs -->
            <div id="drilldown-ips-bulk-bar" class="bulk-actions-toolbar mb-4" style="display: none;">
              <div class="flex items-center gap-2">
                <span class="bulk-count-badge" id="drilldown-ips-bulk-count">0</span>
                <span class="text-sm font-medium">IPs selected</span>
              </div>
              <div class="flex items-center gap-2">
                <button type="button" class="btn btn-secondary btn-sm" onclick="clearIpSelection()">Deselect All</button>
                <button type="button" class="btn btn-danger btn-sm" onclick="deleteSelectedIps(this)">
                  🗑️ Delete Selected IPs (<span id="drilldown-ips-bulk-btn-count">0</span>)
                </button>
              </div>
            </div>

            ${filteredFips.length === 0 ? `
              <div class="data-table-container text-center py-8 text-secondary">
                ${accFips.length === 0 ? `
                  No floating IPs allocated in <strong>${escapeHtml(acc.label)}</strong>.<br>
                  <button class="btn btn-primary btn-sm mt-3" onclick="openAllocIpModal(${acc.id})">⚡ + Allocate Floating IP</button>
                ` : `
                  No floating IPs match the filter (<b>${escapeHtml(currentFilter)}</b>).
                `}
              </div>
            ` : `
              <div class="data-table-container">
                <div class="table-responsive">
                  <table class="data-table">
                    <thead>
                      <tr>
                        <th style="width: 38px; text-align: center;">
                          <input type="checkbox" id="cb-select-all-drilldown-fips" class="checkbox-input" onchange="toggleSelectAllIpsInTable(this, 'drilldown-fips-tbody')" title="Select all Floating IPs">
                        </th>
                        <th>Floating IP & Reverse DNS</th>
                        <th>Type</th>
                        <th>Location</th>
                        <th>Assignment Status</th>
                        <th class="text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody id="drilldown-fips-tbody">
                      ${filteredFips.map(f => {
                        const ipVal = f.ip || f.subnet || f.ip_address;
                        const isAttached = !!f.server_id;
                        const srv = isAttached ? state.servers.find(s => s.account_id === acc.id && String(s.id) === String(f.server_id)) : null;
                        const srvLabel = srv ? (srv.name || srv.label || '#' + f.server_id) : (f.server_id ? '#' + f.server_id : '');
                        const revDns = formatReverseDnsText(f.dns_ptr || f.reverse || '');
                        const isSelected = state.selectedIps && state.selectedIps.has(`${acc.id}:${f.id}:floating`);

                        return `
                          <tr>
                            <td style="width: 38px; text-align: center;" onclick="event.stopPropagation()">
                              <input type="checkbox" class="cb-ip-select checkbox-input"
                                data-acc-id="${acc.id}"
                                data-ip-id="${f.id}"
                                data-ip="${escapeHtml(ipVal)}"
                                data-type="floating"
                                ${isSelected ? 'checked' : ''}
                                onchange="toggleIpSelection(${acc.id}, '${f.id}', '${escapeHtml(ipVal)}', 'floating', this)">
                            </td>
                            <td>
                              <div class="flex flex-col gap-1">
                                <div class="flex items-center gap-1.5 flex-wrap">
                                  <span class="ip-copyable" onclick="copyText('${escapeHtml(ipVal)}')">
                                    <code class="font-mono text-sm font-bold text-primary">${escapeHtml(ipVal)}</code>
                                    <span class="text-xs text-muted" title="Copy IP address">📋</span>
                                  </span>
                                  ${f.name ? `<span class="badge badge-secondary text-xs">${escapeHtml(f.name)}</span>` : ''}
                                </div>
                                ${revDns ? `
                                  <div class="flex items-center gap-1 text-xs text-secondary font-mono">
                                    <span class="text-tertiary">PTR:</span>
                                    <span class="truncate" style="max-width: 180px;" title="${escapeHtml(revDns)}">${escapeHtml(revDns)}</span>
                                    <span class="cursor-pointer text-muted hover-text-primary" onclick="copyText('${escapeHtml(revDns)}')" title="Copy Reverse DNS">📋</span>
                                  </div>
                                ` : ''}
                              </div>
                            </td>
                            <td><span class="badge text-xs uppercase">${escapeHtml(f.type || 'ipv4')}</span></td>
                            <td><span class="text-xs text-secondary">${escapeHtml(f.location || f.region || '—')}</span></td>
                            <td>
                              ${isAttached ? `
                                <span class="badge badge-status-running cursor-pointer" onclick="openServerDetailsModal(${acc.id}, '${f.server_id}')" title="Click to view instance details">Attached to ${escapeHtml(srvLabel)}</span>
                              ` : `
                                <span class="badge badge-warning">⚠️ Free / Not Attached</span>
                              `}
                            </td>
                            <td class="text-right">
                              <div class="flex items-center justify-end gap-1.5 flex-wrap">
                                ${isAttached ? `
                                  <button class="btn btn-secondary btn-sm" onclick="unassignFloatingIp(${acc.id}, '${f.id}', this)" title="Detach IP from server">🔓 Detach</button>
                                  <button class="btn btn-danger btn-sm" onclick="deleteFloatingIp(${acc.id}, '${f.id}', '${escapeHtml(ipVal)}', this)" title="Detach and permanently delete Floating IP">🗑️ Detach & Delete</button>
                                ` : `
                                  <button class="btn btn-primary btn-sm" onclick="openAttachFipModal('${f.id}', ${acc.id}, '${escapeHtml(ipVal)}')" title="Attach Floating IP to server">🔗 Attach</button>
                                  <button class="btn btn-danger btn-sm" onclick="deleteFloatingIp(${acc.id}, '${f.id}', '${escapeHtml(ipVal)}', this)" title="Permanently delete unassigned Floating IP">🗑️ Delete IP</button>
                                `}
                              </div>
                            </td>
                          </tr>
                        `;
                      }).join("")}
                    </tbody>
                  </table>
                </div>
              </div>
            `}
          </div>

          <!-- SECTION 2: Hetzner Primary IPs (Dedicated Separate Card) -->
          ${provider === 'hetzner' ? `
            <div class="hetzner-ip-section-card mt-6">
              <div class="flex items-center justify-between mb-3 flex-wrap gap-2">
                <div>
                  <h3 class="text-base font-bold text-primary flex items-center gap-2">
                    <span>🏷️ Hetzner Primary IPs</span>
                    <span class="badge badge-hetzner text-xs">${accPrimaryIps.length}</span>
                  </h3>
                  <div class="text-xs text-secondary mt-0.5">Fixed primary interface network IPs allocated directly to Hetzner instances</div>
                </div>
              </div>

              ${accPrimaryIps.length === 0 ? `
                <div class="data-table-container text-center py-6 text-muted">
                  No Primary IPs found for this account.
                </div>
              ` : `
                <div class="data-table-container">
                  <div class="table-responsive">
                    <table class="data-table">
                      <thead>
                        <tr>
                          <th style="width: 38px; text-align: center;">
                            <input type="checkbox" id="cb-select-all-drilldown-pips" class="checkbox-input" onchange="toggleSelectAllIpsInTable(this, 'drilldown-pips-tbody')" title="Select all Primary IPs">
                          </th>
                          <th>Primary IP</th>
                          <th>Type</th>
                          <th>Datacenter</th>
                          <th>Assigned Instance</th>
                          <th>Auto Delete</th>
                          <th class="text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody id="drilldown-pips-tbody">
                        ${accPrimaryIps.map(p => {
                          const isAssigned = !!p.assignee_id;
                          const srv = isAssigned ? state.servers.find(s => s.account_id === acc.id && String(s.id) === String(p.assignee_id)) : null;
                          const srvLabel = srv ? (srv.name || srv.label || '#' + p.assignee_id) : (p.assignee_id ? '#' + p.assignee_id : '');
                          const isSelected = state.selectedIps && state.selectedIps.has(`${acc.id}:${p.id}:primary`);

                          return `
                            <tr>
                              <td style="width: 38px; text-align: center;" onclick="event.stopPropagation()">
                                <input type="checkbox" class="cb-ip-select checkbox-input"
                                  data-acc-id="${acc.id}"
                                  data-ip-id="${p.id}"
                                  data-ip="${escapeHtml(p.ip)}"
                                  data-type="primary"
                                  ${isSelected ? 'checked' : ''}
                                  onchange="toggleIpSelection(${acc.id}, ${p.id}, '${escapeHtml(p.ip)}', 'primary', this)">
                              </td>
                              <td>
                                <div class="flex items-center gap-1.5 flex-wrap">
                                  <span class="ip-copyable" onclick="copyText('${escapeHtml(p.ip)}')">
                                    <code class="font-mono text-sm font-bold text-primary">${escapeHtml(p.ip)}</code>
                                    <span class="text-xs text-muted" title="Copy IP">📋</span>
                                  </span>
                                  ${p.name ? `<span class="badge badge-secondary text-xs">${escapeHtml(p.name)}</span>` : ''}
                                </div>
                              </td>
                              <td><span class="badge text-xs uppercase">${escapeHtml(p.type || 'ipv4')}</span></td>
                              <td><span class="text-xs text-secondary">${escapeHtml(p.datacenter || '—')}</span></td>
                              <td>
                                ${isAssigned ? `
                                  <span class="badge badge-status-running cursor-pointer" onclick="openServerDetailsModal(${acc.id}, '${p.assignee_id}')" title="View assigned server">
                                    Assigned to ${escapeHtml(srvLabel)}
                                  </span>
                                ` : `
                                  <span class="badge badge-status-off">Free / Unbound</span>
                                `}
                              </td>
                              <td><span class="text-xs text-secondary">${p.auto_delete ? 'Yes (with server)' : 'No (Retained)'}</span></td>
                              <td class="text-right">
                                <button class="btn btn-danger btn-sm" onclick="deletePrimaryIp(${acc.id}, ${p.id}, this)" title="Permanently delete Hetzner Primary IP">🗑️ Delete IP</button>
                              </td>
                            </tr>
                          `;
                        }).join("")}
                      </tbody>
                    </table>
                  </div>
                </div>
              `}
            </div>
          ` : ''}
        </div>
      `;
    }

    serversView.innerHTML = html;
  }
}

function setProviderIpFilter(filter, provider) {
  state.providerIpFilter = filter;
  renderProviderHubView(provider);
}
window.setProviderIpFilter = setProviderIpFilter;

function renderHetznerHub() {
  renderProviderHubView("hetzner");
}

function renderVultrHub() {
  renderProviderHubView("vultr");
}

function renderLinodeHub() {
  renderProviderHubView("linode");
}

// ---- ALL COMPUTE TABLE ----
function renderAllCompute() {
  const filter = document.getElementById("filter-all-provider").value;
  let srvs = state.servers;
  if (filter !== "all") {
    srvs = srvs.filter(s => s.provider === filter);
  }
  renderServersTable(srvs, "all-compute-tbody");
}

function renderServersTable(servers, tbodyId) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;

  if (servers.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center py-8 text-secondary">No instances found.</td></tr>`;
    return;
  }

  tbody.innerHTML = servers.map(s => renderServerRow(s, true, true, true)).join("");
  updateBulkActionBars();
}

function renderServerRow(s, showProviderCol = true, showFipsCol = true, showCheckboxCol = true) {
  const isRunning = isServerRunning(s.status);
  const isSelected = state.selectedServers && state.selectedServers.has(`${s.account_id}:${s.id}`);
  const fips = (s.floating_ips || []).map(f => `
    <span class="ip-copyable" onclick="copyText('${escapeHtml(f.ip)}')">
      <code class="font-mono text-xs">${escapeHtml(f.ip)}</code>
    </span>
  `).join("") || '<span class="text-muted text-xs">—</span>';

  return `
    <tr id="server-row-${s.id}" data-server-id="${s.id}">
      ${showCheckboxCol ? `
      <td style="width: 38px; text-align: center;" onclick="event.stopPropagation()">
        <input type="checkbox" class="cb-server-select" data-acc-id="${s.account_id}" data-srv-id="${s.id}" data-provider="${s.provider}" data-label="${escapeHtml(s.name || s.label || s.id)}" ${isSelected ? 'checked' : ''} onchange="toggleServerSelection(${s.account_id}, '${s.id}', '${escapeHtml(s.name || s.label || s.id)}', '${s.provider}', this)">
      </td>` : ''}
      <td>
        <div class="font-bold text-primary server-title-link flex items-center gap-1.5" onclick="openServerDetailsModal(${s.account_id}, '${s.id}')" title="Manage Server & IPs">
          <span>${escapeHtml(s.name || s.label || s.id)}</span>
          <span class="text-xs text-muted">↗</span>
        </div>
        <div class="text-xs text-muted font-mono">ID: ${s.id}</div>
      </td>
      <td>
        <span class="badge ${isRunning ? 'badge-status-running' : 'badge-status-off'}">
          <span class="w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-success' : 'bg-muted'}"></span>
          ${s.status || 'running'}
        </span>
      </td>
      ${showProviderCol ? `
      <td>
        <div class="flex items-center gap-1.5">
          ${getProviderBadge(s.provider)}
        </div>
        <div class="text-xs text-secondary mt-0.5">${escapeHtml(s.account_label || '')}</div>
      </td>` : ''}
      <td>
        <div class="font-medium">${escapeHtml(s.region || '—')}</div>
      </td>
      <td>
        ${s.ip ? `
          <span class="ip-copyable" onclick="copyText('${s.ip}')" title="Click to copy">
            <code class="font-mono text-sm">${s.ip}</code>
            <span class="text-xs text-muted">📋</span>
          </span>
        ` : '<span class="text-muted">—</span>'}
      </td>
      ${showFipsCol ? `<td>${fips}</td>` : ''}
      <td><span class="text-xs font-mono text-secondary">${escapeHtml(s.plan || '—')}</span></td>
      <td class="text-right">
        <div class="flex items-center justify-end gap-1">
          <button class="btn btn-secondary btn-sm" onclick="openServerDetailsModal(${s.account_id}, '${s.id}')" title="Server Overview, IPs & SSH">🖥️ Manage</button>
          <button class="btn btn-secondary btn-sm" onclick="powerServer(${s.account_id}, '${s.id}', 'reboot')" title="Reboot">🔄</button>
          <button class="btn btn-secondary btn-sm" onclick="powerServer(${s.account_id}, '${s.id}', '${isRunning ? 'halt' : 'start'}')" title="${isRunning ? 'Halt/Stop' : 'Start'}">${isRunning ? '⏸️' : '▶️'}</button>
          <button class="btn btn-secondary btn-sm" onclick="showServerPassword(${s.account_id}, '${s.id}')" title="Show Root Password">🔐</button>
          <button class="btn btn-danger btn-sm" onclick="deleteServer(${s.account_id}, '${s.id}', '${escapeHtml(s.name || s.label || s.id)}')" title="Delete">🗑️</button>
        </div>
      </td>
    </tr>
  `;
}

// ---- BULK SERVER SELECTION & DELETION ----
function toggleServerSelection(accId, srvId, label, provider, cb) {
  const key = `${accId}:${srvId}`;
  if (!state.selectedServers) state.selectedServers = new Map();
  if (cb.checked) {
    state.selectedServers.set(key, { account_id: accId, server_id: srvId, label: label, provider: provider });
  } else {
    state.selectedServers.delete(key);
  }
  updateBulkActionBars();
}
window.toggleServerSelection = toggleServerSelection;

function toggleSelectAllInView(masterCb, tbodyId) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  if (!state.selectedServers) state.selectedServers = new Map();
  const cbs = tbody.querySelectorAll(".cb-server-select");
  cbs.forEach(cb => {
    cb.checked = masterCb.checked;
    const accId = parseInt(cb.getAttribute("data-acc-id"));
    const srvId = cb.getAttribute("data-srv-id");
    const label = cb.getAttribute("data-label");
    const prov = cb.getAttribute("data-provider");
    const key = `${accId}:${srvId}`;
    if (masterCb.checked) {
      state.selectedServers.set(key, { account_id: accId, server_id: srvId, label: label, provider: prov });
    } else {
      state.selectedServers.delete(key);
    }
  });
  updateBulkActionBars();
}
window.toggleSelectAllInView = toggleSelectAllInView;

function clearServerSelection() {
  if (state.selectedServers) {
    state.selectedServers.clear();
  }
  document.querySelectorAll(".cb-server-select, .cb-select-all").forEach(cb => {
    cb.checked = false;
  });
  updateBulkActionBars();
}
window.clearServerSelection = clearServerSelection;

function updateBulkActionBars() {
  const count = state.selectedServers ? state.selectedServers.size : 0;
  
  // Compute tab bar
  const computeBar = document.getElementById("compute-bulk-bar");
  const computeCount = document.getElementById("compute-bulk-count");
  const computeBtnCount = document.getElementById("compute-bulk-btn-count");
  if (computeBar) {
    computeBar.style.display = count > 0 ? "flex" : "none";
    if (computeCount) computeCount.textContent = count;
    if (computeBtnCount) computeBtnCount.textContent = count;
  }

  // Drilldown tab bar
  const drillBar = document.getElementById("drilldown-bulk-bar");
  const drillCount = document.getElementById("drilldown-bulk-count");
  const drillBtnCount = document.getElementById("drilldown-bulk-btn-count");
  if (drillBar) {
    drillBar.style.display = count > 0 ? "flex" : "none";
    if (drillCount) drillCount.textContent = count;
    if (drillBtnCount) drillBtnCount.textContent = count;
  }
}
window.updateBulkActionBars = updateBulkActionBars;

async function deleteSelectedServers(btn) {
  if (!state.selectedServers || state.selectedServers.size === 0) {
    showToast("No instances selected", "warning");
    return;
  }
  const items = Array.from(state.selectedServers.values());
  const count = items.length;
  const serverNames = items.slice(0, 5).map(s => s.label).join(", ") + (count > 5 ? ` and ${count - 5} more` : "");

  const confirmed = await confirmAction({
    title: `Delete ${count} Instances?`,
    message: `Are you sure you want to permanently delete these ${count} instances (${escapeHtml(serverNames)})? This action cannot be undone and will terminate all selected cloud servers immediately.`,
    confirmText: `🗑️ Delete ${count} Instances`,
    isDanger: true
  });
  if (!confirmed) return;

  await runWithButtonLoading(btn, async () => {
    let successCount = 0;
    let failCount = 0;
    const errors = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      try {
        await api("delete_server", {
          account_id: item.account_id,
          server_id: item.server_id,
          confirm: "DELETE_SERVER"
        });
        successCount++;
        state.selectedServers.delete(`${item.account_id}:${item.server_id}`);
      } catch (err) {
        failCount++;
        errors.push(`${item.label}: ${err.message}`);
      }
    }

    if (failCount === 0) {
      showToast(`Successfully deleted all ${successCount} selected instances!`, "success");
    } else if (successCount > 0) {
      showToast(`Deleted ${successCount} instances, but ${failCount} failed: ${errors.slice(0, 2).join("; ")}`, "warning");
    } else {
      showToast(`Failed to delete instances: ${errors.slice(0, 2).join("; ")}`, "error");
    }

    clearServerSelection();
    await loadAll();
  }, `Deleting ${count} instances...`);
}
window.deleteSelectedServers = deleteSelectedServers;

// ---- BULK IP SELECTION & DELETION ----
function toggleIpSelection(accId, ipId, ipText, type, cb) {
  const key = `${accId}:${ipId}:${type}`;
  if (!state.selectedIps) state.selectedIps = new Map();
  if (cb.checked) {
    state.selectedIps.set(key, { account_id: accId, ip_id: ipId, ip: ipText, type: type, key: key });
  } else {
    state.selectedIps.delete(key);
  }
  updateIpBulkActionBars();
}
window.toggleIpSelection = toggleIpSelection;

function toggleSelectAllIpsInTable(masterCb, tbodyId) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  if (!state.selectedIps) state.selectedIps = new Map();
  const cbs = tbody.querySelectorAll(".cb-ip-select");
  cbs.forEach(cb => {
    cb.checked = masterCb.checked;
    const accId = parseInt(cb.getAttribute("data-acc-id"));
    const ipId = cb.getAttribute("data-ip-id");
    const ip = cb.getAttribute("data-ip");
    const type = cb.getAttribute("data-type") || "floating";
    const key = `${accId}:${ipId}:${type}`;
    if (masterCb.checked) {
      state.selectedIps.set(key, { account_id: accId, ip_id: ipId, ip: ip, type: type, key: key });
    } else {
      state.selectedIps.delete(key);
    }
  });
  updateIpBulkActionBars();
}
window.toggleSelectAllIpsInTable = toggleSelectAllIpsInTable;

function clearIpSelection() {
  if (state.selectedIps) {
    state.selectedIps.clear();
  }
  document.querySelectorAll(".cb-ip-select, #cb-select-all-fips, #cb-select-all-pips, #cb-select-all-drilldown-fips, #cb-select-all-drilldown-pips").forEach(cb => {
    cb.checked = false;
  });
  updateIpBulkActionBars();
}
window.clearIpSelection = clearIpSelection;

function updateIpBulkActionBars() {
  const count = state.selectedIps ? state.selectedIps.size : 0;

  // Global IP Management tab bulk bar
  const ipsBar = document.getElementById("ips-bulk-bar");
  const ipsCount = document.getElementById("ips-bulk-count");
  const ipsBtnCount = document.getElementById("ips-bulk-btn-count");
  if (ipsBar) {
    ipsBar.style.display = count > 0 ? "flex" : "none";
    if (ipsCount) ipsCount.textContent = count;
    if (ipsBtnCount) ipsBtnCount.textContent = count;
  }

  // Drilldown tab IP bulk bar
  const drillIpsBar = document.getElementById("drilldown-ips-bulk-bar");
  const drillIpsCount = document.getElementById("drilldown-ips-bulk-count");
  const drillIpsBtnCount = document.getElementById("drilldown-ips-bulk-btn-count");
  if (drillIpsBar) {
    drillIpsBar.style.display = count > 0 ? "flex" : "none";
    if (drillIpsCount) drillIpsCount.textContent = count;
    if (drillIpsBtnCount) drillIpsBtnCount.textContent = count;
  }
}
window.updateIpBulkActionBars = updateIpBulkActionBars;

async function deleteSelectedIps(btn) {
  if (!state.selectedIps || state.selectedIps.size === 0) {
    showToast("No IPs selected", "warning");
    return;
  }
  const items = Array.from(state.selectedIps.values());
  const count = items.length;
  const ipList = items.slice(0, 5).map(x => x.ip).join(", ") + (count > 5 ? ` and ${count - 5} more` : "");

  const confirmed = await confirmAction({
    title: `Delete ${count} IPs?`,
    message: `Are you sure you want to permanently delete these ${count} selected IPs (${escapeHtml(ipList)})? This will detach and delete them from your cloud accounts immediately.`,
    expectedWord: "DELETE_IPS",
    isDanger: true
  });
  if (!confirmed) return;

  await runWithButtonLoading(btn, async () => {
    let successCount = 0;
    let failCount = 0;
    const errors = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      try {
        if (item.type === "primary") {
          await api("delete_hetzner_primary_ip", {
            account_id: item.account_id,
            ip_id: item.ip_id,
            confirm: "DELETE_PRIMARY_IP"
          });
        } else {
          await api("delete_floating_ip", {
            account_id: item.account_id,
            floating_id: item.ip_id,
            confirm: "DELETE_FLOATING_IP"
          });
        }
        successCount++;
        state.selectedIps.delete(item.key);
      } catch (err) {
        failCount++;
        errors.push(`${item.ip}: ${err.message}`);
      }
    }

    if (failCount === 0) {
      showToast(`Successfully deleted all ${successCount} selected IPs!`, "success");
    } else if (successCount > 0) {
      showToast(`Deleted ${successCount} IPs, but ${failCount} failed: ${errors.slice(0, 2).join("; ")}`, "warning");
    } else {
      showToast(`Failed to delete IPs: ${errors.slice(0, 2).join("; ")}`, "error");
    }

    clearIpSelection();
    await loadAll();
  }, `Deleting ${count} IPs...`);
}
window.deleteSelectedIps = deleteSelectedIps;

// ---- TAB 6: IP MANAGEMENT ----
function setIpsAccountFilter(accFilter) {
  state.ipsAccountFilter = String(accFilter);
  renderIPManagement();
}
window.setIpsAccountFilter = setIpsAccountFilter;

function renderIPManagement() {
  const currentFilter = state.ipsAccountFilter || "all";

  // 1. Render Account Filter Pills
  const pillsContainer = document.getElementById("ips-account-filter-pills");
  if (pillsContainer) {
    const totalAllFips = state.floatingIps.length;
    const totalAllPips = state.primaryIps.length;
    const totalAll = totalAllFips + totalAllPips;

    let pillsHtml = `
      <div class="ips-account-pill ${currentFilter === 'all' ? 'active' : ''}" onclick="setIpsAccountFilter('all')">
        <span>All Accounts</span>
        <span class="pill-badge">${totalAll}</span>
      </div>
    `;

    state.accounts.forEach(acc => {
      const accFipsCount = state.floatingIps.filter(f => f.account_id === acc.id).length;
      const accPipsCount = (acc.provider === 'hetzner') ? state.primaryIps.filter(p => p.account_id === acc.id).length : 0;
      const accTotal = accFipsCount + accPipsCount;
      const provIcon = acc.provider === 'hetzner' ? '🇩🇪' : (acc.provider === 'vultr' ? '🌊' : '🟢');

      pillsHtml += `
        <div class="ips-account-pill ${currentFilter === String(acc.id) ? 'active' : ''}" onclick="setIpsAccountFilter(${acc.id})">
          <span>${provIcon} ${escapeHtml(acc.label)}</span>
          <span class="pill-badge">${accTotal}</span>
        </div>
      `;
    });
    pillsContainer.innerHTML = pillsHtml;
  }

  // 2. Filter data
  let fips = state.floatingIps;
  let pips = state.primaryIps;
  let showPrimarySection = true;

  if (currentFilter !== "all") {
    const filterAccId = parseInt(currentFilter);
    const selectedAcc = state.accounts.find(a => a.id === filterAccId);
    fips = fips.filter(f => f.account_id === filterAccId);
    pips = pips.filter(p => p.account_id === filterAccId);
    if (selectedAcc && selectedAcc.provider !== "hetzner") {
      showPrimarySection = false;
    }
  }

  // Update Section Badges
  const fBadge = document.getElementById("floating-ips-count-badge");
  if (fBadge) fBadge.textContent = fips.length;
  const pBadge = document.getElementById("primary-ips-count-badge");
  if (pBadge) pBadge.textContent = pips.length;

  const pWrapper = document.getElementById("hetzner-primary-ips-wrapper");
  if (pWrapper) {
    pWrapper.style.display = showPrimarySection ? "block" : "none";
  }

  // 3. Render Floating IPs Table
  const tbody = document.getElementById("ips-tbody");
  if (tbody) {
    if (fips.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-secondary">No floating or reserved IPs found. Click "+ Allocate New Floating IP" above.</td></tr>`;
    } else {
      tbody.innerHTML = fips.map(f => {
        const safeId = "ip-row-" + (f.ip || '').replace(/[^a-zA-Z0-9]/g, '_');
        const attachedSrv = f.server_id ? (state.servers || []).find(s => String(s.id) === String(f.server_id)) : null;
        const attachedLabel = attachedSrv ? `Attached #${f.server_id} (${attachedSrv.name || attachedSrv.label})` : `Attached #${f.server_id}`;
        let ptrDisplay = '—';
        if (Array.isArray(f.dns_ptr) && f.dns_ptr.length > 0) {
          ptrDisplay = f.dns_ptr.map(d => typeof d === 'object' ? (d.dns_ptr || d.ip) : d).filter(Boolean).join(', ');
        } else if (typeof f.dns_ptr === 'string') {
          ptrDisplay = f.dns_ptr;
        } else if (f.description) {
          ptrDisplay = f.description;
        }
        const isSelected = state.selectedIps && state.selectedIps.has(`${f.account_id}:${f.id}:floating`);
        return `
          <tr id="${safeId}" data-ip="${escapeHtml(f.ip)}">
            <td style="width: 38px; text-align: center;" onclick="event.stopPropagation()">
              <input type="checkbox" class="cb-ip-select" data-acc-id="${f.account_id}" data-ip-id="${f.id}" data-ip="${escapeHtml(f.ip)}" data-type="floating" ${isSelected ? 'checked' : ''} onchange="toggleIpSelection(${f.account_id}, '${f.id}', '${escapeHtml(f.ip)}', 'floating', this)">
            </td>
            <td>
              <span class="ip-copyable" onclick="copyText('${escapeHtml(f.ip)}')">
                <code class="font-mono text-sm font-bold text-primary">${escapeHtml(f.ip)}</code>
                <span class="text-xs text-muted">📋</span>
              </span>
            </td>
            <td><span class="badge text-xs uppercase">${f.type || 'ipv4'}</span></td>
            <td>
              <div class="flex items-center gap-1">${getProviderBadge(f.provider)}</div>
              <div class="text-xs text-secondary mt-0.5">${escapeHtml(f.account_label || '')}</div>
            </td>
            <td>${escapeHtml(f.location || '—')}</td>
            <td>
              ${f.server_id ? `<span class="badge badge-status-running" title="Server ID: ${f.server_id}">${escapeHtml(attachedLabel)}</span>` : '<span class="badge badge-unassigned">⚠️ Unassigned</span>'}
            </td>
            <td>
              <span class="truncate font-mono text-xs text-secondary" style="max-width: 180px; display: inline-block;" title="${escapeHtml(ptrDisplay)}">${escapeHtml(ptrDisplay)}</span>
            </td>
            <td class="text-right">
              <div class="flex items-center justify-end gap-1.5 flex-wrap">
                ${f.server_id ? `
                  <button class="btn btn-secondary btn-sm" onclick="unassignFloatingIp(${f.account_id}, '${f.id}', this)" title="Detach from server">🔓 Detach</button>
                  <button class="btn btn-danger btn-sm" onclick="deleteFloatingIp(${f.account_id}, '${f.id}', '${escapeHtml(f.ip)}', this)" title="Detach and delete">🗑️ Detach & Delete</button>
                ` : `
                  <button class="btn btn-primary btn-sm" onclick="openAttachFipModal('${f.id}', ${f.account_id}, '${escapeHtml(f.ip)}')" title="Attach to server">🔗 Attach</button>
                  <button class="btn btn-danger btn-sm" onclick="deleteFloatingIp(${f.account_id}, '${f.id}', '${escapeHtml(f.ip)}', this)" title="Permanently delete IP">🗑️ Delete IP</button>
                `}
              </div>
            </td>
          </tr>
        `;
      }).join("");
    }
  }

  // 4. Render Primary IPs Table
  const pbody = document.getElementById("primary-ips-tbody");
  if (pbody && showPrimarySection) {
    if (pips.length === 0) {
      pbody.innerHTML = `<tr><td colspan="8" class="text-center py-6 text-muted">No Hetzner Primary IPs found.</td></tr>`;
    } else {
      pbody.innerHTML = pips.map(p => {
        const safeId = "ip-row-" + (p.ip || '').replace(/[^a-zA-Z0-9]/g, '_');
        const isSelected = state.selectedIps && state.selectedIps.has(`${p.account_id}:${p.id}:primary`);
        return `
          <tr id="${safeId}" data-ip="${escapeHtml(p.ip)}">
            <td style="width: 38px; text-align: center;" onclick="event.stopPropagation()">
              <input type="checkbox" class="cb-ip-select" data-acc-id="${p.account_id}" data-ip-id="${p.id}" data-ip="${escapeHtml(p.ip)}" data-type="primary" ${isSelected ? 'checked' : ''} onchange="toggleIpSelection(${p.account_id}, '${p.id}', '${escapeHtml(p.ip)}', 'primary', this)">
            </td>
            <td><code class="font-mono text-sm font-bold text-primary">${escapeHtml(p.ip)}</code></td>
            <td><span class="badge text-xs uppercase">${p.type}</span></td>
            <td><span class="text-xs text-secondary">${escapeHtml(p.account_label || '')}</span></td>
            <td>${escapeHtml(p.datacenter || '—')}</td>
            <td>${p.assignee_id ? `<span class="badge badge-status-running">#${p.assignee_id}</span>` : '<span class="badge badge-status-off">Free</span>'}</td>
            <td>${p.auto_delete ? 'Yes' : 'No'}</td>
            <td class="text-right">
              <button class="btn btn-danger btn-sm" onclick="deletePrimaryIp(${p.account_id}, ${p.id}, this)" title="Delete Hetzner Primary IP">🗑️ Delete</button>
            </td>
          </tr>
        `;
      }).join("");
    }
  }
  updateIpBulkActionBars();
}

// ---- TAB 7: SSH KEYS ----
function renderSSHKeys() {
  const tbody = document.getElementById("ssh-keys-tbody");
  if (state.sshKeys.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center py-8 text-secondary">No SSH keys found in vault. Add or generate a key above.</td></tr>`;
    return;
  }
  tbody.innerHTML = state.sshKeys.map(k => `
    <tr>
      <td>
        <div class="font-bold text-primary">${escapeHtml(k.name)}</div>
        <div class="text-xs text-muted font-mono">#${k.id}</div>
      </td>
      <td><code class="font-mono text-xs text-secondary">${escapeHtml(k.fingerprint || '—')}</code></td>
      <td>
        <span class="ip-copyable" onclick="copyText('${escapeHtml(k.public_key)}')">
          <code class="font-mono text-xs">${escapeHtml(k.public_key.slice(0, 32))}...</code>
          <span class="text-xs text-muted">📋</span>
        </span>
      </td>
      <td class="text-xs text-secondary">${new Date(k.created_at * 1000).toLocaleDateString()}</td>
      <td class="text-right">
        <button class="btn btn-danger btn-sm" onclick="deleteSshKey(${k.id}, '${escapeHtml(k.name)}')">Delete</button>
      </td>
    </tr>
  `).join("");
}

// ---- TAB 8: CLOUDFLARE DNS ----
function renderDNS() {
  const zoneSelect = document.getElementById("select-dns-zone");
  if (!zoneSelect) return;
  if (!state.dnsZones || state.dnsZones.length === 0) {
    zoneSelect.innerHTML = `<option value="">No Cloudflare zones configured</option>`;
  } else {
    zoneSelect.innerHTML = `<option value="">Select Cloudflare Zone...</option>` +
      state.dnsZones.map(z => `<option value="${z.id}">${escapeHtml(z.name)}</option>`).join("");
  }
}

async function loadDnsRecords(zoneId) {
  const tbody = document.getElementById("dns-records-tbody");
  tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-secondary">Loading zone DNS records...</td></tr>`;
  try {
    const res = await api("dns_records", { zone_id: zoneId });
    const records = res.records || [];
    if (records.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-secondary">No DNS records found in this zone.</td></tr>`;
      return;
    }
    tbody.innerHTML = records.map(r => `
      <tr>
        <td><div class="font-bold text-primary font-mono text-xs">${escapeHtml(r.name)}</div></td>
        <td><span class="badge text-xs uppercase">${r.type}</span></td>
        <td><code class="font-mono text-xs text-primary">${escapeHtml(r.content)}</code></td>
        <td>${r.proxied ? '<span class="badge" style="background:#f97316;color:#fff">Proxied (Orange)</span>' : '<span class="badge badge-status-off">DNS Only (Grey)</span>'}</td>
        <td class="text-xs text-secondary">${r.ttl === 1 ? 'Auto' : r.ttl + 's'}</td>
        <td class="text-right">
          <button class="btn btn-danger btn-sm" onclick="deleteDnsRecord('${zoneId}', '${r.id}')">Delete</button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-danger">${err.message}</td></tr>`;
  }
}

// ---- TAB 9: WATCHDOG & TUNNELS ----
function renderWatchdog() {
  if (state.watchdog) {
    document.getElementById("watchdog-state").textContent = state.watchdog.enabled ? "Active ✅" : "Disabled ❌";
    document.getElementById("watchdog-last-probe").textContent = `Cap: ${state.watchdog.daily_cap || 3} repairs/day · Interval: ${state.watchdog.interval || 300}s`;
  }
  document.getElementById("stat-tunnels-count").textContent = state.tunnels.length;

  const tbody = document.getElementById("tunnels-tbody");
  if (state.tunnels.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-secondary">No tunnels registered.</td></tr>`;
    return;
  }
  tbody.innerHTML = state.tunnels.map(t => `
    <tr>
      <td><code class="font-mono text-xs font-bold">#${t.id}</code></td>
      <td><span class="badge text-xs uppercase">${t.kind}</span></td>
      <td><code class="font-mono text-xs">${escapeHtml(t.foreign_host || '—')}</code></td>
      <td><code class="font-mono text-xs">${escapeHtml(t.iran_host || '—')}</code></td>
      <td><span class="text-xs font-mono text-secondary">${escapeHtml(t.ports || '—')}</span></td>
    </tr>
  `).join("");
}

// Route mapping for clean multi-page URL navigation
const ROUTE_MAP = {
  "/": "tab-overview",
  "/overview": "tab-overview",
  "/accounts": "tab-accounts",
  "/proxies": "tab-proxies",
  "/hetzner": "tab-hetzner",
  "/vultr": "tab-vultr",
  "/linode": "tab-linode",
  "/compute": "tab-compute",
  "/ips": "tab-ips",
  "/ssh": "tab-ssh",
  "/dns": "tab-dns",
  "/watchdog": "tab-watchdog"
};

const TAB_TO_ROUTE = {
  "tab-overview": "/overview",
  "tab-accounts": "/accounts",
  "tab-proxies": "/proxies",
  "tab-hetzner": "/hetzner",
  "tab-vultr": "/vultr",
  "tab-linode": "/linode",
  "tab-compute": "/compute",
  "tab-ips": "/ips",
  "tab-ssh": "/ssh",
  "tab-dns": "/dns",
  "tab-watchdog": "/watchdog"
};

// ==================== NAVIGATION & TAB SWITCHING ====================
function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const sidebarContent = document.querySelector(".sidebar-content");
  const mobileToggle = document.getElementById("btn-mobile-nav");

  if (mobileToggle && sidebarContent) {
    mobileToggle.addEventListener("click", () => {
      sidebarContent.classList.toggle("mobile-open");
    });
  }

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetTab = item.getAttribute("data-tab");
      if (targetTab === "tab-hetzner") state.providerSelectedAccount.hetzner = null;
      if (targetTab === "tab-vultr") state.providerSelectedAccount.vultr = null;
      if (targetTab === "tab-linode") state.providerSelectedAccount.linode = null;
      switchTab(targetTab, true);
    });
  });

  // Overview Hero Card jumps
  document.querySelectorAll("[data-jump-tab]").forEach(el => {
    el.addEventListener("click", () => {
      const targetTab = el.getAttribute("data-jump-tab");
      if (targetTab === "tab-hetzner") state.providerSelectedAccount.hetzner = null;
      if (targetTab === "tab-vultr") state.providerSelectedAccount.vultr = null;
      if (targetTab === "tab-linode") state.providerSelectedAccount.linode = null;
      switchTab(targetTab, true);
    });
  });

  // Filter change in All Compute
  document.getElementById("filter-all-provider").addEventListener("change", renderAllCompute);

  // DNS Zone change
  document.getElementById("select-dns-zone").addEventListener("change", (e) => {
    if (e.target.value) loadDnsRecords(e.target.value);
  });

  // Refresh button
  document.getElementById("btn-refresh-all").addEventListener("click", () => loadAll(true));

  // Handle browser back and forward buttons
  window.addEventListener("popstate", (e) => {
    const tabId = (e.state && e.state.tabId) || ROUTE_MAP[window.location.pathname] || "tab-overview";
    switchTab(tabId, false);
  });

  // Switch to initial tab from address bar URL
  const initialPath = window.location.pathname;
  if (ROUTE_MAP[initialPath]) {
    switchTab(ROUTE_MAP[initialPath], false);
  }
}

function switchTab(tabId, pushState = true) {
  state.activeTab = tabId;
  const sidebarContent = document.querySelector(".sidebar-content");
  if (sidebarContent) sidebarContent.classList.remove("mobile-open");

  document.querySelectorAll(".nav-item").forEach(item => {
    item.classList.toggle("active", item.getAttribute("data-tab") === tabId);
  });
  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === tabId);
  });

  const titles = {
    "tab-overview": "Infrastructure Overview",
    "tab-accounts": "Cloud Account & Billing Center",
    "tab-proxies": "Proxy Pool & Management",
    "tab-hetzner": "Hetzner Cloud Hub",
    "tab-vultr": "Vultr Cloud Hub",
    "tab-linode": "Linode / Akamai Hub",
    "tab-compute": "All Compute Instances",
    "tab-ips": "Floating & Reserved IP Management",
    "tab-ssh": "SSH Key Vault",
    "tab-dns": "Cloudflare DNS Management",
    "tab-watchdog": "Watchdog Probing & Tunnels"
  };
  const title = titles[tabId] || "Hosting Console";
  document.getElementById("view-title").textContent = title;
  document.title = `${title} | Cloudbot`;

  // Push state to browser history if requested
  if (pushState && TAB_TO_ROUTE[tabId]) {
    const targetRoute = TAB_TO_ROUTE[tabId];
    if (window.location.pathname !== targetRoute) {
      window.history.pushState({ tabId }, title, targetRoute);
    }
  }

  if (tabId === "tab-accounts") renderAccountsManagement();
  if (tabId === "tab-proxies") renderProxyManagement();
  if (tabId === "tab-hetzner") renderHetznerHub();
  if (tabId === "tab-vultr") renderVultrHub();
  if (tabId === "tab-linode") renderLinodeHub();
  if (tabId === "tab-compute") renderAllCompute();
  if (tabId === "tab-ips") renderIPManagement();
  if (tabId === "tab-ssh") renderSSHKeys();
  if (tabId === "tab-dns") renderDNS();
  if (tabId === "tab-watchdog") renderWatchdog();
}

// ==================== SEARCH ====================
function highlightSearchMatch(text, query) {
  if (!text) return "";
  const str = String(text);
  if (!query) return escapeHtml(str);
  try {
    const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escapedQuery})`, "gi");
    const parts = str.split(regex);
    return parts.map((part, i) =>
      i % 2 === 1
        ? `<mark>${escapeHtml(part)}</mark>`
        : escapeHtml(part)
    ).join("");
  } catch (e) {
    return escapeHtml(str);
  }
}

function initSearch() {
  const searchInput = document.getElementById("global-search-input");
  const clearBtn = document.getElementById("btn-search-clear");
  const dropdown = document.getElementById("global-search-dropdown");
  const resultsContainer = document.getElementById("global-search-results");
  const summaryEl = document.getElementById("search-results-summary");
  const kbdHint = document.getElementById("search-kbd-hint");

  if (!searchInput) return;

  // Slash shortcut to focus
  window.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== searchInput && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName)) {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
  });

  function performSearch() {
    try {
      const rawVal = searchInput.value;
      const q = rawVal.trim().toLowerCase();

      if (!q) {
        if (dropdown) dropdown.classList.remove("open");
        if (clearBtn) clearBtn.classList.remove("visible");
        if (kbdHint) kbdHint.style.display = "";
        renderServersTable(state.servers, "all-compute-tbody");
        return;
      }

      if (clearBtn) clearBtn.classList.add("visible");
      if (kbdHint) kbdHint.style.display = "none";

      // 1. Matches in Servers / Instances (Instant SQLite Cache)
      const matchedServers = (state.servers || []).filter(s => {
        const name = String(s.name || s.label || '').toLowerCase();
        const ip = String(s.ip || '').toLowerCase();
        const ips = (s.ips || []).map(x => String(x || '').toLowerCase()).join(' ');
        const ipv4 = (Array.isArray(s.ipv4) ? s.ipv4.join(' ') : String(s.ipv4 || '')).toLowerCase();
        const ipv6 = (Array.isArray(s.ipv6) ? s.ipv6.join(' ') : String(s.ipv6 || '')).toLowerCase();
        const id = String(s.id || '').toLowerCase();
        const prov = String(s.provider || '').toLowerCase();
        const acc = String(s.account_label || '').toLowerCase();
        const reg = String(s.region || '').toLowerCase();
        const plan = String(s.plan || '').toLowerCase();
        const fips = (s.floating_ips || []).map(f => String(f.ip || f.ip_address || f.subnet || f.network || '').toLowerCase()).join(' ');
        return name.includes(q) || ip.includes(q) || ips.includes(q) || ipv4.includes(q) || ipv6.includes(q) || id.includes(q) || prov.includes(q) || acc.includes(q) || reg.includes(q) || plan.includes(q) || fips.includes(q);
      });

      // 2. Matches in Floating & Primary IPs
      const allIps = [
        ...(state.floatingIps || []).map(f => ({ ...f, provider: f.provider || 'hetzner', ipType: 'Floating IP' })),
        ...(state.primaryIps || []).map(p => ({ ...p, provider: p.provider || 'hetzner', ipType: 'Primary IP' }))
      ];
      const matchedIps = allIps.filter(f => {
        const ip = String(f.ip || f.ip_address || f.subnet || f.network || '').toLowerCase();
        const name = String(f.name || f.server_name || '').toLowerCase();
        const prov = String(f.provider || '').toLowerCase();
        const reg = String(f.region || '').toLowerCase();
        const acc = String(f.account_label || '').toLowerCase();
        const id = String(f.id || '').toLowerCase();
        const srvId = String(f.server_id || f.assignee_id || '').toLowerCase();
        return ip.includes(q) || name.includes(q) || prov.includes(q) || reg.includes(q) || acc.includes(q) || id.includes(q) || srvId.includes(q);
      });

      // 3. Matches in Cloud Accounts
      const matchedAccounts = (state.accounts || []).filter(a => {
        const label = String(a.label || '').toLowerCase();
        const prov = String(a.provider || '').toLowerCase();
        const reg = String(a.region || '').toLowerCase();
        const email = String(a.email || '').toLowerCase();
        const id = String(a.id || '').toLowerCase();
        return label.includes(q) || prov.includes(q) || reg.includes(q) || email.includes(q) || id.includes(q);
      });

      // Update underlying tables as well
      renderServersTable(matchedServers, "all-compute-tbody");

      const totalMatches = matchedServers.length + matchedIps.length + matchedAccounts.length;
      if (summaryEl) {
        summaryEl.textContent = totalMatches > 0
          ? `${totalMatches} match${totalMatches === 1 ? '' : 'es'} found`
          : "No results";
      }

      if (!resultsContainer) return;

      if (totalMatches === 0) {
        resultsContainer.innerHTML = `
          <div class="search-empty-state">
            <div class="search-empty-icon">🔍</div>
            <div class="font-bold text-primary">No infrastructure matches for "${escapeHtml(rawVal)}"</div>
            <div class="text-xs text-muted mt-1">Search by server name, public IP, region code, cloud provider, or account</div>
          </div>
        `;
        if (dropdown) dropdown.classList.add("open");
        return;
      }

      let html = "";

      // Instances Group
      if (matchedServers.length > 0) {
        const displayServers = matchedServers.slice(0, 8);
        html += `
          <div class="search-category-group">
            <div class="search-category-title">
              <span>🖥️</span> Instances (${matchedServers.length})
            </div>
            ${displayServers.map(s => {
              const isRunning = isServerRunning(s.status);
              const matchingFips = (s.floating_ips || []).filter(f => String(f.ip || f.ip_address || f.subnet || f.network || '').toLowerCase().includes(q));
              return `
                <div class="search-result-item" tabindex="0" data-action="server" data-server-id="${escapeHtml(s.id)}" data-account-id="${s.account_id}">
                  <div class="search-item-main">
                    <div class="search-item-icon">🖥️</div>
                    <div class="search-item-info">
                      <div class="search-item-title">
                        <span>${highlightSearchMatch(s.name || s.label || s.id, rawVal)}</span>
                      </div>
                      <div class="search-item-sub">
                        <code>${highlightSearchMatch(s.ip || 'No IP', rawVal)}</code>
                        ${matchingFips.length > 0 ? `
                          <span>•</span>
                          <span class="badge badge-secondary" style="font-size:0.65rem;padding:1px 5px;">FIP: ${matchingFips.map(f => highlightSearchMatch(f.ip, rawVal)).join(', ')}</span>
                        ` : ''}
                        <span>•</span>
                        <span>${highlightSearchMatch(s.region || '—', rawVal)}</span>
                        <span>•</span>
                        <span>${highlightSearchMatch(s.account_label || '', rawVal)}</span>
                      </div>
                    </div>
                  </div>
                  <div class="search-item-badges">
                    ${getProviderBadge(s.provider)}
                    <span class="badge ${isRunning ? 'badge-status-running' : 'badge-status-off'}" style="font-size:0.68rem;padding:2px 6px;">
                      ${s.status || 'running'}
                    </span>
                  </div>
                </div>
              `;
            }).join("")}
            ${matchedServers.length > 8 ? `
              <div class="text-xs text-secondary text-center py-1 cursor-pointer hover:underline" onclick="switchTab('tab-compute');document.getElementById('global-search-dropdown').classList.remove('open');">
                + ${matchedServers.length - 8} more instances in All Compute →
              </div>
            ` : ''}
          </div>
        `;
      }

      // Floating & Primary IPs Group
      if (matchedIps.length > 0) {
        const displayIps = matchedIps.slice(0, 6);
        html += `
          <div class="search-category-group">
            <div class="search-category-title">
              <span>🌐</span> Floating & Primary IPs (${matchedIps.length})
            </div>
            ${displayIps.map(f => {
              const srv = (f.server_id || f.assignee_id) ? (state.servers || []).find(s => String(s.id) === String(f.server_id || f.assignee_id)) : null;
              const srvLabel = srv ? (srv.name || srv.label) : (f.server_name || f.name || 'Unassigned');
              return `
              <div class="search-result-item" tabindex="0" data-action="ip" data-ip="${escapeHtml(f.ip)}" data-account-id="${f.account_id}">
                <div class="search-item-main">
                  <div class="search-item-icon">🌐</div>
                  <div class="search-item-info">
                    <div class="search-item-title font-mono font-bold">
                      <span>${highlightSearchMatch(f.ip, rawVal)}</span>
                    </div>
                    <div class="search-item-sub">
                      <span class="badge badge-secondary" style="font-size:0.65rem;padding:1px 5px;">${f.ipType}</span>
                      <span>•</span>
                      <span>${highlightSearchMatch(srvLabel, rawVal)}</span>
                      <span>•</span>
                      <span>${highlightSearchMatch(f.account_label || '', rawVal)}</span>
                    </div>
                  </div>
                </div>
                <div class="search-item-badges">
                  ${getProviderBadge(f.provider)}
                </div>
              </div>
            `;
            }).join("")}
          </div>
        `;
      }

      // Accounts Group
      if (matchedAccounts.length > 0) {
        const displayAccounts = matchedAccounts.slice(0, 6);
        html += `
          <div class="search-category-group">
            <div class="search-category-title">
              <span>🔑</span> Cloud Accounts (${matchedAccounts.length})
            </div>
            ${displayAccounts.map(a => `
              <div class="search-result-item" tabindex="0" data-action="account" data-account-id="${a.id}">
                <div class="search-item-main">
                  <div class="search-item-icon">🔑</div>
                  <div class="search-item-info">
                    <div class="search-item-title">
                      <span>${highlightSearchMatch(a.label, rawVal)}</span>
                    </div>
                    <div class="search-item-sub">
                      <span>Region: ${highlightSearchMatch(a.region || 'Default', rawVal)}</span>
                      <span>•</span>
                      <span class="font-mono text-xs">ID: ${a.id}</span>
                    </div>
                  </div>
                </div>
                <div class="search-item-badges">
                  ${getProviderBadge(a.provider)}
                </div>
              </div>
            `).join("")}
          </div>
        `;
      }

      resultsContainer.innerHTML = html;
      if (dropdown) dropdown.classList.add("open");
    } catch (err) {
      console.error("Search execution failed:", err);
    }
  }

  searchInput.addEventListener("input", performSearch);

  searchInput.addEventListener("focus", () => {
    if (searchInput.value.trim()) {
      performSearch();
    }
  });

  // Clear button click
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      searchInput.value = "";
      if (dropdown) dropdown.classList.remove("open");
      clearBtn.classList.remove("visible");
      if (kbdHint) kbdHint.style.display = "";
      renderServersTable(state.servers, "all-compute-tbody");
      searchInput.focus();
    });
  }

  // Dismiss on clicking outside
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".header-search")) {
      if (dropdown) dropdown.classList.remove("open");
    }
  });

  // Handle click on results
  if (resultsContainer) {
    resultsContainer.addEventListener("click", (e) => {
      const item = e.target.closest(".search-result-item");
      if (!item) return;

      const action = item.getAttribute("data-action");
      if (dropdown) dropdown.classList.remove("open");

      if (action === "server") {
        const srvId = item.getAttribute("data-server-id");
        const accId = item.getAttribute("data-account-id");
        openServerDetailsModal(accId, srvId);
      } else if (action === "ip") {
        const ip = item.getAttribute("data-ip");
        const accId = item.getAttribute("data-account-id");
        if (state.ipsAccountFilter && state.ipsAccountFilter !== "all" && state.ipsAccountFilter !== String(accId)) {
          setIpsAccountFilter("all");
        }
        switchTab("tab-ips", true);
        setTimeout(() => {
          const safeId = "ip-row-" + (ip || '').replace(/[^a-zA-Z0-9]/g, '_');
          const row = document.getElementById(safeId) ||
            Array.from(document.querySelectorAll("#ips-tbody tr, #primary-ips-tbody tr")).find(r => r.textContent.includes(ip));
          if (row) {
            row.scrollIntoView({ behavior: "smooth", block: "center" });
            row.classList.add("row-highlight-pulse");
            setTimeout(() => row.classList.remove("row-highlight-pulse"), 2500);
          }
        }, 80);
      } else if (action === "account") {
        const accId = item.getAttribute("data-account-id");
        switchTab("tab-accounts", true);
        setTimeout(() => {
          const card = document.getElementById("acc-card-" + accId);
          if (card) {
            card.scrollIntoView({ behavior: "smooth", block: "center" });
            card.classList.add("row-highlight-pulse");
            setTimeout(() => card.classList.remove("row-highlight-pulse"), 2500);
          }
        }, 80);
      }
    });
  }

  // Keyboard navigation inside dropdown
  searchInput.addEventListener("keydown", (e) => {
    if (!dropdown || !dropdown.classList.contains("open")) return;
    const items = resultsContainer ? resultsContainer.querySelectorAll(".search-result-item") : [];

    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (!items.length) return;
      let currentIndex = Array.from(items).findIndex(el => el.classList.contains("selected"));
      if (currentIndex >= 0) items[currentIndex].classList.remove("selected");
      currentIndex = (currentIndex + 1) % items.length;
      items[currentIndex].classList.add("selected");
      items[currentIndex].scrollIntoView({ block: "nearest" });
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (!items.length) return;
      let currentIndex = Array.from(items).findIndex(el => el.classList.contains("selected"));
      if (currentIndex >= 0) items[currentIndex].classList.remove("selected");
      currentIndex = currentIndex <= 0 ? items.length - 1 : currentIndex - 1;
      items[currentIndex].classList.add("selected");
      items[currentIndex].scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter") {
      e.preventDefault();
      const selected = resultsContainer.querySelector(".search-result-item.selected") || items[0];
      if (selected) {
        selected.click();
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      dropdown.classList.remove("open");
      searchInput.blur();
    }
  });
}

// ==================== DEPLOYMENT WIZARD ====================
async function getCachedRegions(accId) {
  const id = parseInt(accId);
  if (state.regionsCache[id]) {
    return state.regionsCache[id];
  }
  const res = await api("regions", { account_id: id });
  state.regionsCache[id] = res.regions || [];
  return state.regionsCache[id];
}

async function getCachedPlans(accId, region) {
  const id = parseInt(accId);
  const cacheKey = `${id}:${region}`;
  if (state.plansCache[cacheKey]) {
    return state.plansCache[cacheKey];
  }
  const res = await api("plans", { account_id: id, region });
  state.plansCache[cacheKey] = res.plans || [];
  return state.plansCache[cacheKey];
}

async function getCachedImages(accId) {
  const id = parseInt(accId);
  if (state.imagesCache[id]) {
    return state.imagesCache[id];
  }
  const res = await api("images", { account_id: id });
  state.imagesCache[id] = res.images || [];
  return state.imagesCache[id];
}

function prefetchAccountDeployOptions(accId) {
  if (!accId) return;
  const id = parseInt(accId);
  getCachedRegions(id).then(regions => {
    const acc = state.accounts.find(a => a.id === id);
    const targetRegion = (acc && acc.region) ? acc.region : (regions[0] ? regions[0].id : null);
    if (targetRegion) {
      getCachedPlans(id, targetRegion).catch(() => {});
    }
  }).catch(() => {});
  getCachedImages(id).catch(() => {});
}
window.prefetchAccountDeployOptions = prefetchAccountDeployOptions;
window.getCachedRegions = getCachedRegions;
window.getCachedPlans = getCachedPlans;
window.getCachedImages = getCachedImages;

function openDeployModalForProvider(prov) {
  state.deploySelectedProvider = prov;
  openModal("modal-deploy-server");
  updateDeployProviderPicker(prov);
  const countInput = document.getElementById("deploy-count-input");
  if (countInput) countInput.value = "1";
  updateDeployCountPreview();

  // Background prefetch for accounts of this provider
  const matching = state.accounts.filter(a => a.provider === prov);
  matching.forEach(a => prefetchAccountDeployOptions(a.id));
}

function openDeployModalForAccount(accId, prov) {
  state.deploySelectedProvider = prov;
  openModal("modal-deploy-server");
  updateDeployProviderPicker(prov);
  const countInput = document.getElementById("deploy-count-input");
  if (countInput) countInput.value = "1";
  updateDeployCountPreview();
  const accSel = document.getElementById("deploy-account-select");
  accSel.value = accId;
  prefetchAccountDeployOptions(accId);
  accSel.dispatchEvent(new Event("change"));
}

function updateDeployProviderPicker(prov) {
  document.querySelectorAll(".provider-picker-btn").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-prov") === prov);
  });

  // Hetzner IPv6 options visibility
  const hetznerOpts = document.getElementById("deploy-hetzner-options");
  if (hetznerOpts) {
    hetznerOpts.style.display = (prov === "hetzner") ? "block" : "none";
    const v6Cb = document.getElementById("deploy-enable-ipv6");
    if (v6Cb) v6Cb.checked = false;
  }

  // Populate accounts matching this provider
  const accSel = document.getElementById("deploy-account-select");
  const matching = state.accounts.filter(a => a.provider === prov);
  accSel.innerHTML = `<option value="">Select ${prov} account...</option>` +
    matching.map(a => `<option value="${a.id}">${escapeHtml(a.label)}</option>`).join("");

  // Reset dependent selectors
  resetDeploySelectors();

  // Populate SSH keys
  const sshSel = document.getElementById("deploy-ssh-select");
  sshSel.innerHTML = `<option value="">Auto-inject all vault SSH keys</option>` +
    state.sshKeys.map(k => `<option value="${k.id}">${escapeHtml(k.name)}</option>`).join("");
}

function resetDeploySelectors() {
  const regSel = document.getElementById("deploy-region-select");
  const planSel = document.getElementById("deploy-plan-select");
  const imgSel = document.getElementById("deploy-image-select");
  regSel.innerHTML = `<option value="">Choose region...</option>`;
  regSel.disabled = true;
  planSel.innerHTML = `<option value="">Choose plan...</option>`;
  planSel.disabled = true;
  imgSel.innerHTML = `<option value="">Choose image...</option>`;
  imgSel.disabled = true;

  const v6Cb = document.getElementById("deploy-enable-ipv6");
  if (v6Cb) v6Cb.checked = false;
}

// ==================== MODALS & FORMS ====================
function initModals() {
  document.querySelectorAll("[data-close]").forEach(btn => {
    btn.addEventListener("click", () => {
      closeModal(btn.getAttribute("data-close"));
    });
  });

  document.querySelectorAll(".modal-backdrop").forEach(backdrop => {
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) closeModal(backdrop.id);
    });
  });

  document.getElementById("btn-open-deploy-modal").addEventListener("click", () => {
    openDeployModalForProvider("hetzner");
  });

  document.getElementById("btn-open-alloc-ip").addEventListener("click", () => {
    openAllocIpModal();
  });
  document.getElementById("btn-alloc-ip-tab").addEventListener("click", () => {
    openAllocIpModal();
  });

  document.getElementById("btn-open-add-account").addEventListener("click", () => {
    openAddAccountModal();
  });

  const accRegInput = document.getElementById("acc-region");
  if (accRegInput) {
    accRegInput.addEventListener("input", () => {
      const val = accRegInput.value.trim().toUpperCase();
      const flagEl = document.getElementById("add-acc-flag-preview");
      if (flagEl) flagEl.textContent = getCountryFlag(val);
      updateAddAccProxyRegionHint(val);
      const poolRadio = document.querySelector('input[name="add-acc-proxy-type"][value="pool"]');
      if (poolRadio && poolRadio.checked) {
        checkAddAccProxyAvailability();
      }
    });
  }

  document.getElementById("btn-add-ssh-key-modal").addEventListener("click", () => {
    openModal("modal-add-ssh");
  });

  document.getElementById("btn-generate-key-modal").addEventListener("click", () => {
    openModal("modal-gen-key");
  });

  // Provider picker click in deployment modal
  document.querySelectorAll(".provider-picker-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const p = btn.getAttribute("data-prov");
      state.deploySelectedProvider = p;
      updateDeployProviderPicker(p);
    });
  });
}

function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add("open");
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove("open");
  if (id === "modal-server-details") {
    clearServerModalFipSelection();
  }
}

function openAddAccountModal(prov) {
  openModal("modal-add-account");
  if (prov) {
    const provEl = document.getElementById("acc-provider");
    if (provEl) provEl.value = prov;
  }
  populateAddAccProxyProviders();
  const hasPool = (state.proxyProviders || []).some(p => p.enabled);
  const defaultMode = hasPool ? "pool" : "none";
  const r = document.querySelector(`input[name="add-acc-proxy-type"][value="${defaultMode}"]`);
  if (r) r.checked = true;
  switchAddAccountProxyMode(defaultMode);
  updateAddAccProxyRegionHint();
}

function openAddAccountModalFor(prov) {
  openAddAccountModal(prov);
}

function resetAllocIpModal() {
  const formFields = document.getElementById("alloc-form-fields");
  const progressBox = document.getElementById("alloc-progress");
  const successBox = document.getElementById("alloc-success");
  const footer = document.getElementById("alloc-footer");
  const submitBtn = document.getElementById("btn-submit-alloc-ip");
  const cancelBtn = document.getElementById("btn-cancel-alloc-ip");
  if (formFields) formFields.style.display = "";
  if (progressBox) progressBox.style.display = "none";
  if (successBox) successBox.style.display = "none";
  if (footer) footer.style.display = "";
  if (submitBtn) {
    submitBtn.disabled = false;
    submitBtn.innerHTML = "<span>Allocate IP</span>";
  }
  if (cancelBtn) cancelBtn.disabled = false;
}

function updateAllocIpAccountServers(accId) {
  const srvSel = document.getElementById("alloc-server-select");
  const locWrap = document.getElementById("alloc-location-wrap");
  if (!srvSel) return;
  if (!accId) {
    srvSel.innerHTML = `<option value="">Keep unassigned (allocate to pool)</option>`;
    if (locWrap) locWrap.style.display = "";
    return;
  }
  const id = parseInt(accId);
  const acc = state.accounts.find(a => a.id === id);
  const accServers = state.servers.filter(s => s.account_id === id);
  srvSel.innerHTML = `<option value="">Keep unassigned (allocate to pool)</option>` +
    accServers.map(s => `<option value="${s.id}">${escapeHtml(s.name || s.label || s.id)} (${s.ip || 'No IP'})</option>`).join("");
  
  if (locWrap) {
    if (acc && acc.provider === "hetzner" && !srvSel.value) {
      locWrap.style.display = "";
    } else {
      locWrap.style.display = "none";
    }
  }
}

function openAllocIpModal(preselectedAccId) {
  resetAllocIpModal();
  openModal("modal-alloc-ip");
  const accSel = document.getElementById("alloc-account-select");
  const eligible = state.accounts.filter(a => a.provider === "hetzner" || a.provider === "vultr");
  accSel.innerHTML = `<option value="">Select Account...</option>` +
    eligible.map(a => `<option value="${a.id}" ${preselectedAccId && a.id === Number(preselectedAccId) ? 'selected' : ''}>[${a.provider}] ${escapeHtml(a.label)}</option>`).join("");
  
  const chosenAccId = preselectedAccId || accSel.value;
  if (chosenAccId) {
    accSel.value = chosenAccId;
    updateAllocIpAccountServers(chosenAccId);
  } else {
    updateAllocIpAccountServers(null);
  }
}
window.openAllocIpModal = openAllocIpModal;

function openAttachFipModal(fipId, accId, ipText) {
  openModal("modal-attach-fip");
  document.getElementById("attach-fip-id").value = fipId;
  document.getElementById("attach-fip-acc-id").value = accId;
  document.getElementById("attach-fip-label").textContent = ipText;

  const targetSel = document.getElementById("attach-target-server-select");
  const accServers = state.servers.filter(s => s.account_id === accId);
  targetSel.innerHTML = `<option value="">Select target instance...</option>` +
    accServers.map(s => `<option value="${s.id}">${escapeHtml(s.name || s.label)} (${s.ip || 'No IP'})</option>`).join("");
}

function openOsConfigModal(ip) {
  openModal("modal-os-config");
  document.getElementById("os-config-cmd").textContent = `ip addr add ${ip}/32 dev eth0`;
  document.getElementById("os-config-netplan").textContent =
`# /etc/netplan/60-floating-ip.yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - ${ip}/32`;
}

// ==================== SERVER DETAILS & MANAGEMENT MODAL (TELEGRAM BOT EXPERIENCE) ====================
let currentServerModal = null;
let currentServerModalAccId = null;
let currentServerModalSrvId = null;
let currentServerModalPw = null;

function copyModalField(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.textContent || el.value || "";
  copyText(text);
}

function switchSrvModalTab(tabName) {
  const tabs = ["overview", "ips", "security"];
  tabs.forEach(t => {
    const btn = document.getElementById(`srvmodal-tab-btn-${t}`);
    const pane = document.getElementById(`srvmodal-pane-${t}`);
    if (btn) btn.classList.toggle("active", t === tabName);
    if (pane) pane.style.display = (t === tabName) ? "block" : "none";
  });
}

function navigateFromModalToAccount() {
  if (!currentServerModal || !currentServerModal.server) return;
  const s = currentServerModal.server;
  const accId = s.account_id || currentServerModalAccId;
  const prov = s.provider;
  closeModal("modal-server-details");
  if (prov && accId) {
    navigateToAccount(prov, accId);
  }
}

function populateServerModalData(s, fips = [], pips = [], linodeNet = null) {
  currentServerModal = { server: s, floating_ips: fips, primary_ips: pips, linode_networking: linodeNet };

  const isRunning = isServerRunning(s.status);
  const label = s.name || s.label || s.id;
  document.getElementById("srvmodal-label").textContent = label;

  // Status badge
  const badge = document.getElementById("srvmodal-status-badge");
  badge.className = `badge ${isRunning ? 'badge-status-running' : 'badge-status-off'}`;
  badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-success' : 'bg-muted'}"></span> ${s.status || (isRunning ? 'running' : 'stopped')}`;

  // Account & Provider
  const accPill = document.getElementById("srvmodal-account-pill");
  accPill.textContent = s.account_label || (s.account_id ? `Account #${s.account_id}` : "Account");
  accPill.title = "Click to view this account";
  document.getElementById("srvmodal-id-text").textContent = `ID: ${s.id}`;

  // Provider Icon
  const provIcon = document.getElementById("srvmodal-provider-icon");
  if (s.provider === "hetzner") provIcon.innerHTML = `🇩🇪`;
  else if (s.provider === "vultr") provIcon.innerHTML = `<img src="/ui/assets/vultr.svg" width="22" height="22" class="object-contain" alt="Vultr">`;
  else if (s.provider === "linode") provIcon.innerHTML = `<img src="/ui/assets/linode.svg" width="22" height="22" class="object-contain" alt="Linode">`;
  else provIcon.innerHTML = `☁️`;

  // Primary IP
  const serverIpv4 = Array.isArray(s.ipv4) ? s.ipv4[0] : s.ipv4;
  const mainIp = s.ip || serverIpv4 || "—";
  document.getElementById("srvmodal-primary-ip").textContent = mainIp;
  document.getElementById("srvmodal-ipv6-sub").textContent = s.ipv6 ? `IPv6: ${s.ipv6}` : "IPv6: None";

  // Region & Flag
  const countryCode = s.country || (s.region ? s.region.slice(0, 2) : "");
  const regInfo = formatRegion(countryCode || s.region);
  document.getElementById("srvmodal-region-flag").textContent = regInfo.flag || "🌐";
  document.getElementById("srvmodal-region-name").textContent = s.region || "Default";
  document.getElementById("srvmodal-country-name").textContent = regInfo.name || (s.region || "—");

  // Plan & Specs
  document.getElementById("srvmodal-plan").textContent = s.plan || "Standard Plan";
  let specStr = "";
  if (s.vcpu_count || s.cores) specStr += `${s.vcpu_count || s.cores} vCPU`;
  if (s.ram) specStr += (specStr ? " · " : "") + `${s.ram} MB RAM`;
  else if (s.memory) specStr += (specStr ? " · " : "") + `${Math.round(s.memory / 1024)} GB RAM`;
  if (s.disk) specStr += (specStr ? " · " : "") + `${s.disk} GB SSD`;
  document.getElementById("srvmodal-specs").textContent = specStr || (s.plan ? `Instance ${s.plan}` : "Cloud Compute");

  // Provider feature (Vultr Auto Backups)
  const backupBtn = document.getElementById("btn-toggle-vultr-backup");
  const featureStatus = document.getElementById("srvmodal-feature-status");
  const featureNote = document.getElementById("srvmodal-feature-note");
  if (s.provider === "vultr") {
    const hasBackup = (s.features || []).includes("auto_backups");
    featureStatus.className = `badge ${hasBackup ? 'badge-status-running' : 'badge-status-off'} text-xs`;
    featureStatus.textContent = hasBackup ? "Auto-Backups Active" : "Auto-Backups Disabled";
    featureNote.textContent = hasBackup ? "Automated snapshot protection enabled" : "No active backup snapshots";
    backupBtn.classList.remove("hidden");
    backupBtn.style.display = "inline-flex";
    backupBtn.textContent = hasBackup ? "💾 Disable" : "💾 Enable";
  } else if (s.provider === "hetzner") {
    featureStatus.className = "badge badge-primary text-xs";
    featureStatus.textContent = "Hetzner Cloud";
    featureNote.textContent = "Primary & Floating IPs supported";
    backupBtn.classList.add("hidden");
    backupBtn.style.display = "none";
  } else {
    featureStatus.className = "badge badge-secondary text-xs";
    featureStatus.textContent = "Linode Compute";
    featureNote.textContent = "Akamai Cloud Infrastructure";
    backupBtn.classList.add("hidden");
    backupBtn.style.display = "none";
  }

  // SSH Commands
  document.getElementById("srvmodal-ssh-box").textContent = `ssh root@${mainIp}`;
  if (currentServerModalPw) {
    document.getElementById("srvmodal-sshpass-box").textContent = `sshpass -p '${currentServerModalPw}' ssh -o StrictHostKeyChecking=no root@${mainIp}`;
  } else {
    document.getElementById("srvmodal-sshpass-box").textContent = `sshpass -p '<password>' ssh -o StrictHostKeyChecking=no root@${mainIp}`;
  }

  // Root Password Preview
  const pwPreview = document.getElementById("srvmodal-preview-password");
  const pwFull = document.getElementById("srvmodal-full-password");
  if (currentServerModalPw) {
    pwPreview.textContent = currentServerModalPw;
    pwFull.textContent = currentServerModalPw;
  } else if (s.has_password) {
    pwPreview.textContent = "••••••••••••••••";
    pwFull.textContent = "••••••••••••••••";
  } else {
    pwPreview.textContent = "Not stored in vault";
    pwFull.textContent = "Not stored in vault";
  }

  // Hetzner Reset Password Box
  const hetzResetBox = document.getElementById("srvmodal-hetzner-reset-box");
  if (s.provider === "hetzner") {
    hetzResetBox.classList.remove("hidden");
    hetzResetBox.style.display = "block";
  } else {
    hetzResetBox.classList.add("hidden");
    hetzResetBox.style.display = "none";
  }

  // Hetzner Primary IP Box
  const hetzPipBox = document.getElementById("srvmodal-hetzner-primary-box");
  if (s.provider === "hetzner" && pips && pips.length > 0) {
    hetzPipBox.classList.remove("hidden");
    hetzPipBox.style.display = "block";
    document.getElementById("srvmodal-hetzner-pip-val").textContent = `${pips[0].ip} (${pips[0].type || 'ipv4'}) - Datacenter: ${pips[0].datacenter || s.region || '—'}`;
  } else {
    hetzPipBox.classList.add("hidden");
    hetzPipBox.style.display = "none";
  }

  // Handle IP Management Tab depending on provider
  const fipsSection = document.getElementById("srvmodal-fips-section");
  const linodeSection = document.getElementById("srvmodal-linode-section");
  const btnAddFip = document.getElementById("btn-srvmodal-add-fip");
  const btnAttachFip = document.getElementById("btn-srvmodal-attach-existing-fip");
  const osGuideIcon = document.getElementById("srvmodal-os-guide-icon");
  const osGuideTitle = document.getElementById("srvmodal-os-guide-title");
  const osGuideText = document.getElementById("srvmodal-os-guide-text");

  if (s.provider === "linode") {
    // Hide floating IP allocate & attach buttons
    if (btnAddFip) btnAddFip.classList.add("hidden");
    if (btnAttachFip) btnAttachFip.classList.add("hidden");
    if (fipsSection) fipsSection.classList.add("hidden");
    if (linodeSection) linodeSection.classList.remove("hidden");

    // Gather Linode IPs
    const linodeIpsList = document.getElementById("srvmodal-linode-ips-list");
    let pubIps = [];
    if (linodeNet && linodeNet.ipv4 && Array.isArray(linodeNet.ipv4.public) && linodeNet.ipv4.public.length > 0) {
      pubIps = linodeNet.ipv4.public.map(x => x.address);
    } else if (Array.isArray(s.ipv4) && s.ipv4.length > 0) {
      pubIps = s.ipv4;
    } else if (s.ip) {
      pubIps = [s.ip];
    }
    const pubIpv6 = (linodeNet && linodeNet.ipv6 && linodeNet.ipv6.slaac) ? linodeNet.ipv6.slaac.address : (s.ipv6 || "");

    let ipCardsHtml = "";
    pubIps.forEach((ip, idx) => {
      ipCardsHtml += `
        <div class="attached-fip-card">
          <div class="flex items-center gap-2">
            <span class="text-lg">🌐</span>
            <div>
              <div class="flex items-center gap-2">
                <code class="font-mono font-bold text-sm text-primary">${escapeHtml(ip)}</code>
                <button type="button" class="btn btn-xs btn-secondary" onclick="copyText('${escapeHtml(ip)}')" title="Copy IP">📋</button>
                <span class="badge badge-primary text-xs uppercase">${idx === 0 ? 'Primary IPv4' : 'Secondary IPv4'}</span>
              </div>
              <div class="text-xs text-secondary mt-0.5">Interface eth0 · Public Routing · Region ${escapeHtml(s.region || '—')}</div>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span class="text-xs text-success font-medium">● Active & Routed</span>
          </div>
        </div>
      `;
    });

    if (pubIpv6) {
      ipCardsHtml += `
        <div class="attached-fip-card">
          <div class="flex items-center gap-2">
            <span class="text-lg">🪐</span>
            <div>
              <div class="flex items-center gap-2">
                <code class="font-mono font-bold text-sm text-primary truncate max-w-xs">${escapeHtml(pubIpv6)}</code>
                <button type="button" class="btn btn-xs btn-secondary" onclick="copyText('${escapeHtml(pubIpv6)}')" title="Copy IPv6">📋</button>
                <span class="badge text-xs uppercase">IPv6 SLAAC</span>
              </div>
              <div class="text-xs text-secondary mt-0.5">Global SLAAC /64 block</div>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span class="text-xs text-success font-medium">● Configured</span>
          </div>
        </div>
      `;
    }

    if (linodeIpsList) linodeIpsList.innerHTML = ipCardsHtml || `<div class="p-4 text-center text-secondary text-sm">No addresses loaded.</div>`;

    // Check for regional peer Linodes to swap IPs
    const accIdForLinode = s.account_id || currentServerModalAccId;
    const peerLinodes = state.servers.filter(x => x.account_id === accIdForLinode && String(x.id) !== String(s.id) && x.region === s.region);
    const swapBtn = document.getElementById("btn-srvmodal-swap-linode-ip");
    if (swapBtn) {
      if (peerLinodes.length > 0) {
        swapBtn.style.display = "inline-flex";
        swapBtn.textContent = `🔄 Swap IP with Regional Peer (${peerLinodes.length} available)`;
      } else {
        swapBtn.style.display = "none";
      }
    }

    document.getElementById("srvmodal-ips-badge").textContent = `${pubIps.length + (pubIpv6 ? 1 : 0)}`;

    if (osGuideIcon) osGuideIcon.textContent = "ℹ️";
    if (osGuideTitle) osGuideTitle.textContent = "Linode (Akamai) IP Architecture";
    if (osGuideText) {
      osGuideText.innerHTML = `
        Linode does not support ephemeral floating IPs. Instead, Linode provides:<br>
        • <b>IP Swap & Transfer:</b> Swap public IPv4 addresses between any Linodes located in the same datacenter (<code>POST /networking/ips/assign</code>).<br>
        • <b>IP Sharing (BGP Failover):</b> Share an IP across multiple instances in the same datacenter (<code>POST /networking/ipv4/share</code>) for high-availability.<br>
        • <b>Additional Public IPv4:</b> Requires submitting a technical justification support ticket to Akamai due to global IPv4 allocation policies.
      `;
    }
  } else {
    // Hetzner or Vultr
    if (btnAddFip) btnAddFip.classList.remove("hidden");
    if (btnAttachFip) btnAttachFip.classList.remove("hidden");
    if (fipsSection) fipsSection.classList.remove("hidden");
    if (linodeSection) linodeSection.classList.add("hidden");

    document.getElementById("srvmodal-ips-badge").textContent = `${fips.length}`;
    const fipsListContainer = document.getElementById("srvmodal-fips-list");
    const fipsSelectRow = document.getElementById("srvmodal-fips-select-row");
    const totalCountBadge = document.getElementById("srvmodal-fips-total-count");
    if (totalCountBadge) totalCountBadge.textContent = `${fips.length}`;

    if (fips.length === 0) {
      if (fipsSelectRow) fipsSelectRow.style.display = "none";
      const bulkBar = document.getElementById("srvmodal-fip-bulk-bar");
      if (bulkBar) bulkBar.style.display = "none";
      fipsListContainer.innerHTML = `
        <div class="p-6 text-center text-secondary text-sm bg-surface rounded-md border border-subtle">
          No floating or reserved IPs currently attached to this server.
          <div class="mt-2 text-xs text-muted">Click <b>+ Allocate & Attach IP</b> or <b>Attach Existing IP</b> above to route dedicated IPs to this instance.</div>
        </div>
      `;
    } else {
      if (fipsSelectRow) fipsSelectRow.style.display = "flex";
      const accIdForFip = s.account_id || currentServerModalAccId;
      fipsListContainer.innerHTML = fips.map(f => {
        const fipVal = f.ip || f.ip_address || f.subnet || f.network || f.id;
        const isSelected = state.selectedServerModalFips && state.selectedServerModalFips.has(String(f.id));
        return `
          <div class="attached-fip-card ${isSelected ? 'selected' : ''}" id="srvmodal-fip-card-${f.id}">
            <div class="flex items-center gap-3">
              <input type="checkbox" class="cb-srvmodal-fip checkbox-input" data-fip-id="${f.id}" data-fip-ip="${escapeHtml(fipVal)}" ${isSelected ? 'checked' : ''} onchange="toggleServerModalFipSelection('${f.id}', '${escapeHtml(fipVal)}', this)" title="Select this IP for batch action">
              <span class="text-lg">🌐</span>
              <div>
                <div class="flex items-center gap-2 flex-wrap">
                  <code class="font-mono font-bold text-sm text-primary">${escapeHtml(fipVal)}</code>
                  <button type="button" class="btn btn-xs btn-secondary" onclick="copyText('${escapeHtml(fipVal)}')" title="Copy IP">📋</button>
                  <span class="badge text-xs uppercase">${f.type || 'ipv4'}</span>
                </div>
                <div class="text-xs text-secondary mt-0.5">${escapeHtml(f.description || f.name || f.dns_ptr || 'Attached Floating IP')}</div>
              </div>
            </div>
            <div class="flex items-center gap-2 flex-wrap">
              <button type="button" class="btn btn-secondary btn-sm" onclick="openOsConfigModal('${escapeHtml(fipVal)}')">Netplan / Config</button>
              <button type="button" class="btn btn-secondary btn-sm" onclick="unassignFloatingIpFromModal(${accIdForFip}, '${f.id}', '${escapeHtml(fipVal)}')">🔓 Detach</button>
              <button type="button" class="btn btn-danger btn-sm" onclick="detachAndDeleteFloatingIpFromModal(${accIdForFip}, '${f.id}', '${escapeHtml(fipVal)}')">🗑️ Detach & Delete</button>
            </div>
          </div>
        `;
      }).join("");
      updateServerModalFipBulkBar();
    }

    if (osGuideIcon) osGuideIcon.textContent = "💡";
    if (osGuideTitle) osGuideTitle.textContent = "Guest OS Network Activation";
    if (osGuideText) {
      osGuideText.innerHTML = `
        Floating IPs route packets to your server, but Linux must recognize the address on interface <code>eth0</code>.
        Click <b>Netplan / Config</b> next to an IP or <b>OS Config Guide</b> below for setup instructions.
      `;
    }
  }

  // Footer Power Button
  const powerBtn = document.getElementById("btn-srvmodal-power");
  powerBtn.textContent = isRunning ? "⏹ Halt / Shutdown" : "▶️ Power On / Boot";
  powerBtn.className = isRunning ? "btn btn-secondary btn-sm" : "btn btn-primary btn-sm";
}

async function openServerDetailsModal(accId, srvId) {
  // Ensure accId is resolved
  if (!accId) {
    const found = state.servers.find(x => String(x.id) === String(srvId));
    if (found) accId = found.account_id;
  }
  currentServerModalAccId = accId;
  currentServerModalSrvId = srvId;
  currentServerModalPw = null;
  clearServerModalFipSelection();

  // 1. Instant render from local cache if present
  const cachedSrv = state.servers.find(x => String(x.id) === String(srvId));
  if (cachedSrv) {
    populateServerModalData(cachedSrv, cachedSrv.floating_ips || [], []);
  } else {
    // Reset modal UI to loading placeholder
    document.getElementById("srvmodal-label").textContent = "Loading instance...";
    document.getElementById("srvmodal-status-badge").className = "badge";
    document.getElementById("srvmodal-status-badge").innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-muted"></span> Loading...`;
    document.getElementById("srvmodal-account-pill").textContent = "Account...";
    document.getElementById("srvmodal-id-text").textContent = `ID: ${srvId}`;
    document.getElementById("srvmodal-primary-ip").textContent = "...";
    document.getElementById("srvmodal-ipv6-sub").textContent = "IPv6: ...";
    document.getElementById("srvmodal-region-flag").textContent = "🌐";
    document.getElementById("srvmodal-region-name").textContent = "...";
    document.getElementById("srvmodal-country-name").textContent = "...";
    document.getElementById("srvmodal-plan").textContent = "...";
    document.getElementById("srvmodal-specs").textContent = "...";
    document.getElementById("srvmodal-feature-status").textContent = "Standard";
    document.getElementById("srvmodal-feature-note").textContent = "...";
    document.getElementById("btn-toggle-vultr-backup").classList.add("hidden");
    document.getElementById("srvmodal-ssh-box").textContent = `ssh root@...`;
    document.getElementById("srvmodal-sshpass-box").textContent = `sshpass -p '••••••' ssh -o StrictHostKeyChecking=no root@...`;
    document.getElementById("srvmodal-preview-password").textContent = "••••••••••••••••";
    document.getElementById("srvmodal-full-password").textContent = "••••••••••••••••";
    document.getElementById("srvmodal-ips-badge").textContent = "0";
    document.getElementById("srvmodal-fips-list").innerHTML = `<div class="p-4 text-center text-secondary text-sm">Loading attached network interfaces...</div>`;
    document.getElementById("srvmodal-hetzner-primary-box").classList.add("hidden");
    document.getElementById("srvmodal-hetzner-reset-box").classList.add("hidden");
  }

  switchSrvModalTab("overview");
  openModal("modal-server-details");

  // 2. Fetch live data from server
  try {
    const res = await api("server", { account_id: accId, server_id: srvId });
    if (res && res.server) {
      populateServerModalData(res.server, res.floating_ips || [], res.primary_ips || [], res.linode_networking);
    }
  } catch (err) {
    if (!cachedSrv) {
      showToast(`Failed to load server details: ${err.message}`, "error");
    }
  }
}

function refreshCurrentServerDetailsModal() {
  if (currentServerModalAccId && currentServerModalSrvId) {
    openServerDetailsModal(currentServerModalAccId, currentServerModalSrvId);
  }
}

async function revealPasswordInServerModal() {
  if (!currentServerModalAccId || !currentServerModalSrvId) return;
  confirmAction("Reveal root password for this server from secure secrets vault?", "SHOW_PASSWORD", async () => {
    try {
      const res = await api("server_password", {
        account_id: currentServerModalAccId,
        server_id: currentServerModalSrvId,
        confirm: "SHOW_PASSWORD"
      });
      const pw = res.password || "Password not stored in vault";
      currentServerModalPw = res.password || "";
      document.getElementById("srvmodal-preview-password").textContent = pw;
      document.getElementById("srvmodal-full-password").textContent = pw;
      if (res.password && currentServerModal && currentServerModal.server) {
        const srv = currentServerModal.server;
        const srvIp = srv.ip || (Array.isArray(srv.ipv4) ? srv.ipv4[0] : srv.ipv4) || '<ip>';
        document.getElementById("srvmodal-sshpass-box").textContent =
          `sshpass -p '${res.password}' ssh -o StrictHostKeyChecking=no root@${srvIp}`;
      }
      showToast("Root password decrypted and revealed.", "success");
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

async function savePasswordFromModal(e) {
  if (e) e.preventDefault();
  if (!currentServerModalAccId || !currentServerModalSrvId) return;
  const input = document.getElementById("srvmodal-new-pw-input");
  const pw = input.value.trim();
  if (!pw) return;
  const btn = document.getElementById("btn-srvmodal-save-pw");

  await runWithButtonLoading(btn, async () => {
    try {
      await api("set_server_password", {
        account_id: currentServerModalAccId,
        server_id: currentServerModalSrvId,
        password: pw
      });
      currentServerModalPw = pw;
      document.getElementById("srvmodal-preview-password").textContent = pw;
      document.getElementById("srvmodal-full-password").textContent = pw;
      if (currentServerModal && currentServerModal.server) {
        currentServerModal.server.has_password = true;
        const srv = currentServerModal.server;
        const srvIp = srv.ip || (Array.isArray(srv.ipv4) ? srv.ipv4[0] : srv.ipv4) || '<ip>';
        document.getElementById("srvmodal-sshpass-box").textContent =
          `sshpass -p '${pw}' ssh -o StrictHostKeyChecking=no root@${srvIp}`;
      }
      input.value = "";
      showToast("Password saved to encrypted secrets vault.", "success");
    } catch (err) {
      showToast(err.message, "error");
    }
  }, "Saving...");
}

async function resetRootPasswordForServer() {
  if (!currentServerModalAccId || !currentServerModalSrvId) return;
  confirmAction("Hetzner will generate a fresh root password and automatically REBOOT this server. This causes temporary downtime. Proceed?", "RESET_PASSWORD", async () => {
    try {
      const res = await api("reset_server_password", {
        account_id: currentServerModalAccId,
        server_id: currentServerModalSrvId,
        confirm: "RESET_PASSWORD"
      });
      const pw = res.password || "";
      currentServerModalPw = pw;
      document.getElementById("srvmodal-preview-password").textContent = pw;
      document.getElementById("srvmodal-full-password").textContent = pw;
      if (pw && currentServerModal && currentServerModal.server) {
        const srv = currentServerModal.server;
        const srvIp = srv.ip || (Array.isArray(srv.ipv4) ? srv.ipv4[0] : srv.ipv4) || '<ip>';
        document.getElementById("srvmodal-sshpass-box").textContent =
          `sshpass -p '${pw}' ssh -o StrictHostKeyChecking=no root@${srvIp}`;
      }
      showToast("New root password generated! Server is rebooting.", "success");
      refreshCurrentServerDetailsModal();
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

async function toggleVultrBackupFromModal() {
  if (!currentServerModal || !currentServerModal.server) return;
  const s = currentServerModal.server;
  const hasBackup = (s.features || []).includes("auto_backups");
  const newStatus = hasBackup ? "disabled" : "enabled";

  try {
    await api("toggle_vultr_backups", {
      account_id: currentServerModalAccId,
      server_id: currentServerModalSrvId,
      status: newStatus
    });
    showToast(`Vultr auto-backups ${newStatus}.`, "success");
    refreshCurrentServerDetailsModal();
    loadAll();
  } catch (err) {
    showToast(err.message, "error");
  }
}

async function rebootServerFromModal() {
  if (!currentServerModalAccId || !currentServerModalSrvId) return;
  await powerServer(currentServerModalAccId, currentServerModalSrvId, "reboot");
  setTimeout(refreshCurrentServerDetailsModal, 1500);
}

async function togglePowerServerFromModal() {
  if (!currentServerModal || !currentServerModal.server) return;
  const isRunning = isServerRunning(currentServerModal.server.status);
  const action = isRunning ? "halt" : "start";
  await powerServer(currentServerModalAccId, currentServerModalSrvId, action);
  setTimeout(refreshCurrentServerDetailsModal, 1500);
}

async function deleteServerFromModal() {
  if (!currentServerModal || !currentServerModal.server) return;
  const s = currentServerModal.server;
  const label = s.name || s.label || currentServerModalSrvId;
  closeModal("modal-server-details");
  await deleteServer(currentServerModalAccId, currentServerModalSrvId, label);
}

function openAllocateFipForServerModal() {
  if (!currentServerModal || !currentServerModal.server) return;
  const s = currentServerModal.server;
  document.getElementById("server-alloc-srv-name").textContent = s.name || s.label || s.id;
  const ipv6Opt = document.getElementById("server-alloc-opt-ipv6");
  if (s.provider === "hetzner") {
    if (ipv6Opt) ipv6Opt.style.display = "";
  } else {
    if (ipv6Opt) ipv6Opt.style.display = "none";
  }

  // Reset modal state
  const formFields = document.getElementById("server-alloc-form-fields");
  const progressBox = document.getElementById("server-alloc-progress");
  const successBox = document.getElementById("server-alloc-success");
  const footer = document.getElementById("server-alloc-footer");
  const submitBtn = document.getElementById("btn-submit-server-alloc");
  const cancelBtn = document.getElementById("btn-cancel-server-alloc");
  if (formFields) formFields.style.display = "";
  if (progressBox) progressBox.style.display = "none";
  if (successBox) successBox.style.display = "none";
  if (footer) footer.style.display = "";
  if (submitBtn) {
    submitBtn.disabled = false;
    submitBtn.innerHTML = "⚡ Allocate & Attach";
  }
  if (cancelBtn) cancelBtn.disabled = false;

  openModal("modal-server-alloc-ip");
}

async function submitAllocateFipForServer(e) {
  if (e) e.preventDefault();
  if (!currentServerModalAccId || !currentServerModalSrvId) return;
  const ipType = document.getElementById("server-alloc-ip-type").value;

  const submitBtn = document.getElementById("btn-submit-server-alloc");
  const cancelBtn = document.getElementById("btn-cancel-server-alloc");
  const formFields = document.getElementById("server-alloc-form-fields");
  const progressBox = document.getElementById("server-alloc-progress");
  const successBox = document.getElementById("server-alloc-success");
  const progressMsg = document.getElementById("server-alloc-progress-msg");
  const footer = document.getElementById("server-alloc-footer");

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="btn-spinner"></span> Allocating Floating IP...`;
  }
  if (cancelBtn) cancelBtn.disabled = true;
  if (formFields) formFields.style.display = "none";
  if (progressBox) progressBox.style.display = "";
  if (progressMsg) progressMsg.textContent = "🌐 Contacting cloud provider...";

  const progressTimer = setTimeout(() => {
    if (progressMsg) progressMsg.textContent = "Configuring floating IP routing...";
  }, 600);

  try {
    const res = await api("create_floating_ip", {
      account_id: currentServerModalAccId,
      server_id: currentServerModalSrvId,
      ip_type: ipType,
      confirm: "CREATE_FLOATING_IP"
    });
    clearTimeout(progressTimer);

    const fip = res.floating_ip || {};
    const fipVal = fip.ip || fip.ip_address || fip.subnet || fip.network || 'Allocated IP';
    const isV6 = (fip.type === 'ipv6' || ipType === 'ipv6');
    const osCmd = isV6 ? `ip -6 addr add ${fipVal}/64 dev eth0` : `ip addr add ${fipVal}/32 dev eth0`;
    const s = currentServerModal ? currentServerModal.server : null;
    const srvLabel = s ? (s.name || s.label || s.id) : currentServerModalSrvId;

    showToast(`Floating ${ipType.toUpperCase()} allocated and attached!`, "success");
    loadAll();
    refreshCurrentServerDetailsModal();

    if (progressBox) progressBox.style.display = "none";
    if (footer) footer.style.display = "none";
    if (successBox) {
      successBox.style.display = "";
      successBox.innerHTML = `
        <div class="p-4 text-center">
          <div class="inline-flex items-center justify-center w-12 h-12 rounded-full mb-2" style="background: rgba(16, 185, 129, 0.15); font-size: 1.5rem;">✅</div>
          <h4 class="text-base font-bold text-primary">Floating IP Allocated & Attached!</h4>
          <p class="text-xs text-secondary mt-1">Successfully attached to <strong class="text-primary">${escapeHtml(srvLabel)}</strong></p>

          <div class="my-4 p-3 bg-surface rounded-md border border-subtle flex items-center justify-between gap-3">
            <div class="text-left">
              <div class="text-xs text-secondary font-medium">New Floating IP</div>
              <code class="font-mono text-lg font-bold text-primary">${escapeHtml(fipVal)}</code>
            </div>
            <button type="button" class="btn btn-sm btn-secondary" onclick="copyText('${escapeHtml(fipVal)}')">📋 Copy IP</button>
          </div>

          <div class="p-3 bg-surface rounded-md border border-subtle text-left mb-4">
            <div class="flex items-between justify-between mb-1">
              <span class="text-xs text-secondary font-medium">Guest OS Activation (eth0)</span>
              <button type="button" class="btn btn-xs btn-secondary" onclick="copyText('${osCmd}')">Copy Command</button>
            </div>
            <code class="font-mono text-xs text-primary block break-all bg-black p-2 rounded">${osCmd}</code>
            <div class="text-xs text-muted mt-1.5">Run with root privileges on the server to activate traffic routing immediately.</div>
          </div>

          <div class="flex items-center justify-center gap-2 pt-2">
            <button type="button" class="btn btn-secondary btn-sm" onclick="closeModal('modal-server-alloc-ip')">Close</button>
            <button type="button" class="btn btn-primary btn-sm" onclick="closeModal('modal-server-alloc-ip'); refreshCurrentServerDetailsModal();">🖥️ View Server Details</button>
          </div>
        </div>
      `;
    }
  } catch (err) {
    clearTimeout(progressTimer);
    showToast(err.message, "error");
    if (progressBox) progressBox.style.display = "none";
    if (formFields) formFields.style.display = "";
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = "⚡ Allocate & Attach";
    }
    if (cancelBtn) cancelBtn.disabled = false;
  }
}

function openAttachExistingFipForServerModal() {
  if (!currentServerModal || !currentServerModal.server) return;
  const s = currentServerModal.server;
  document.getElementById("server-attach-existing-srv-name").textContent = s.name || s.label || s.id;

  // Filter floating IPs belonging to this account that are unassigned
  const unassigned = state.floatingIps.filter(f => f.account_id === currentServerModalAccId && !f.server_id);
  if (unassigned.length === 0) {
    showToast("No unassigned floating IPs found in this account. Allocate a new IP instead.", "info");
    return;
  }

  const sel = document.getElementById("server-attach-existing-select");
  sel.innerHTML = `<option value="">Select unassigned IP...</option>` +
    unassigned.map(f => `<option value="${f.id}">${f.ip} (${f.type || 'ipv4'}) - ${f.location || ''}</option>`).join("");
  openModal("modal-server-attach-existing-ip");
}

async function submitAttachExistingFipForServer(e) {
  if (e) e.preventDefault();
  if (!currentServerModalAccId || !currentServerModalSrvId) return;
  const fipId = document.getElementById("server-attach-existing-select").value;
  if (!fipId) return;
  const btn = document.getElementById("btn-submit-server-attach-existing");

  await runWithButtonLoading(btn, async () => {
    try {
      await api("assign_floating_ip", {
        account_id: currentServerModalAccId,
        server_id: currentServerModalSrvId,
        floating_id: fipId
      });
      showToast("Floating IP successfully attached to instance!", "success");
      closeModal("modal-server-attach-existing-ip");
      refreshCurrentServerDetailsModal();
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  }, "Attaching IP...");
}

async function unassignFloatingIpFromModal(accId, fipId, fipIp) {
  confirmAction(`Detach floating IP ${fipIp} from this server?`, "DETACH", async () => {
    try {
      await api("unassign_floating_ip", { account_id: accId, floating_id: fipId });
      showToast("Floating IP detached.", "success");
      if (state.selectedServerModalFips) {
        state.selectedServerModalFips.delete(String(fipId));
        updateServerModalFipBulkBar();
      }
      refreshCurrentServerDetailsModal();
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

async function detachAndDeleteFloatingIpFromModal(accId, fipId, fipIp) {
  confirmAction(`Detach and permanently delete Floating IP ${fipIp}?`, "DELETE_FLOATING_IP", async () => {
    try {
      await api("delete_floating_ip", { account_id: accId, floating_id: fipId, confirm: "DELETE_FLOATING_IP" });
      showToast("Floating IP detached and deleted.", "success");
      if (state.selectedServerModalFips) {
        state.selectedServerModalFips.delete(String(fipId));
        updateServerModalFipBulkBar();
      }
      refreshCurrentServerDetailsModal();
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

// ---- SERVER MODAL FLOATING IP MULTI-SELECT & BULK ACTIONS ----
function toggleServerModalFipSelection(fipId, fipIp, cb) {
  if (!state.selectedServerModalFips) state.selectedServerModalFips = new Map();
  const accId = currentServerModal?.server?.account_id || currentServerModalAccId;
  const key = String(fipId);
  if (cb.checked) {
    state.selectedServerModalFips.set(key, { id: fipId, ip: fipIp, accId: accId });
    const card = document.getElementById(`srvmodal-fip-card-${fipId}`);
    if (card) card.classList.add("selected");
  } else {
    state.selectedServerModalFips.delete(key);
    const card = document.getElementById(`srvmodal-fip-card-${fipId}`);
    if (card) card.classList.remove("selected");
  }
  updateServerModalFipBulkBar();
}
window.toggleServerModalFipSelection = toggleServerModalFipSelection;

function toggleSelectAllServerModalFips(masterCb) {
  if (!state.selectedServerModalFips) state.selectedServerModalFips = new Map();
  const fips = currentServerModal?.floating_ips || [];
  const accId = currentServerModal?.server?.account_id || currentServerModalAccId;

  if (masterCb.checked) {
    fips.forEach(f => {
      const fipVal = f.ip || f.ip_address || f.subnet || f.network || f.id;
      state.selectedServerModalFips.set(String(f.id), { id: f.id, ip: fipVal, accId: accId });
    });
  } else {
    state.selectedServerModalFips.clear();
  }

  const cbs = document.querySelectorAll("#srvmodal-fips-list .cb-srvmodal-fip");
  cbs.forEach(cb => {
    cb.checked = masterCb.checked;
    const fipId = cb.getAttribute("data-fip-id");
    const card = document.getElementById(`srvmodal-fip-card-${fipId}`);
    if (card) card.classList.toggle("selected", masterCb.checked);
  });

  updateServerModalFipBulkBar();
}
window.toggleSelectAllServerModalFips = toggleSelectAllServerModalFips;

function clearServerModalFipSelection() {
  if (state.selectedServerModalFips) {
    state.selectedServerModalFips.clear();
  }
  const masterCb = document.getElementById("srvmodal-select-all-fips");
  if (masterCb) {
    masterCb.checked = false;
    masterCb.indeterminate = false;
  }
  document.querySelectorAll("#srvmodal-fips-list .cb-srvmodal-fip").forEach(cb => {
    cb.checked = false;
  });
  document.querySelectorAll("#srvmodal-fips-list .attached-fip-card").forEach(card => {
    card.classList.remove("selected");
  });
  updateServerModalFipBulkBar();
}
window.clearServerModalFipSelection = clearServerModalFipSelection;

function updateServerModalFipBulkBar() {
  const count = state.selectedServerModalFips ? state.selectedServerModalFips.size : 0;
  const bar = document.getElementById("srvmodal-fip-bulk-bar");
  const countEl = document.getElementById("srvmodal-fip-bulk-count");
  const detachCountEl = document.getElementById("srvmodal-bulk-detach-count");
  const deleteCountEl = document.getElementById("srvmodal-bulk-delete-count");

  if (bar) bar.style.display = count > 0 ? "flex" : "none";
  if (countEl) countEl.textContent = count;
  if (detachCountEl) detachCountEl.textContent = count;
  if (deleteCountEl) deleteCountEl.textContent = count;

  const totalFips = currentServerModal?.floating_ips?.length || 0;
  const masterCb = document.getElementById("srvmodal-select-all-fips");
  if (masterCb) {
    if (totalFips === 0 || count === 0) {
      masterCb.checked = false;
      masterCb.indeterminate = false;
    } else if (count === totalFips) {
      masterCb.checked = true;
      masterCb.indeterminate = false;
    } else {
      masterCb.checked = false;
      masterCb.indeterminate = true;
    }
  }
}
window.updateServerModalFipBulkBar = updateServerModalFipBulkBar;

async function detachSelectedFipsFromModal(btn) {
  if (!state.selectedServerModalFips || state.selectedServerModalFips.size === 0) {
    showToast("No IPs selected", "warning");
    return;
  }
  const items = Array.from(state.selectedServerModalFips.values());
  const count = items.length;
  const ipList = items.slice(0, 5).map(x => x.ip).join(", ") + (count > 5 ? ` and ${count - 5} more` : "");

  const confirmed = await confirmAction({
    title: `Detach ${count} Floating IPs?`,
    message: `Detach ${count} floating IP${count > 1 ? 's' : ''} (${escapeHtml(ipList)}) from this server? They will remain available in your cloud account pool.`,
    expectedWord: "DETACH",
    confirmText: "Detach IPs",
    isDanger: false
  });
  if (!confirmed) return;

  await runWithButtonLoading(btn, async () => {
    let successCount = 0;
    let failCount = 0;
    const errors = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      try {
        await api("unassign_floating_ip", { account_id: item.accId, floating_id: item.id });
        successCount++;
        state.selectedServerModalFips.delete(String(item.id));
      } catch (err) {
        failCount++;
        errors.push(`${item.ip}: ${err.message}`);
      }
    }

    if (failCount === 0) {
      showToast(`Successfully detached all ${successCount} selected IPs.`, "success");
    } else if (successCount > 0) {
      showToast(`Detached ${successCount} IPs, but ${failCount} failed: ${errors.slice(0, 2).join("; ")}`, "warning");
    } else {
      showToast(`Failed to detach IPs: ${errors.slice(0, 2).join("; ")}`, "error");
    }

    clearServerModalFipSelection();
    refreshCurrentServerDetailsModal();
    loadAll();
  });
}
window.detachSelectedFipsFromModal = detachSelectedFipsFromModal;

async function detachAndDeleteSelectedFipsFromModal(btn) {
  if (!state.selectedServerModalFips || state.selectedServerModalFips.size === 0) {
    showToast("No IPs selected", "warning");
    return;
  }
  const items = Array.from(state.selectedServerModalFips.values());
  const count = items.length;
  const ipList = items.slice(0, 5).map(x => x.ip).join(", ") + (count > 5 ? ` and ${count - 5} more` : "");

  const confirmed = await confirmAction({
    title: `Detach & Delete ${count} Floating IPs?`,
    message: `Permanently delete ${count} floating IP${count > 1 ? 's' : ''} (${escapeHtml(ipList)})? This will detach and delete them from your cloud account immediately. This action cannot be undone!`,
    expectedWord: "DELETE_FLOATING_IP",
    confirmText: "Detach & Delete IPs",
    isDanger: true
  });
  if (!confirmed) return;

  await runWithButtonLoading(btn, async () => {
    let successCount = 0;
    let failCount = 0;
    const errors = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      try {
        await api("delete_floating_ip", {
          account_id: item.accId,
          floating_id: item.id,
          confirm: "DELETE_FLOATING_IP"
        });
        successCount++;
        state.selectedServerModalFips.delete(String(item.id));
      } catch (err) {
        failCount++;
        errors.push(`${item.ip}: ${err.message}`);
      }
    }

    if (failCount === 0) {
      showToast(`Successfully deleted all ${successCount} selected IPs.`, "success");
    } else if (successCount > 0) {
      showToast(`Deleted ${successCount} IPs, but ${failCount} failed: ${errors.slice(0, 2).join("; ")}`, "warning");
    } else {
      showToast(`Failed to delete IPs: ${errors.slice(0, 2).join("; ")}`, "error");
    }

    clearServerModalFipSelection();
    refreshCurrentServerDetailsModal();
    loadAll();
  });
}
window.detachAndDeleteSelectedFipsFromModal = detachAndDeleteSelectedFipsFromModal;

function openHetznerPrimarySwitchFromModal() {
  closeModal("modal-server-details");
  switchTab("tab-ips");
  showToast("Showing Hetzner Primary IPs for reassignment.", "info");
}

function updateDeployCountPreview() {
  const countInput = document.getElementById("deploy-count-input");
  const nameInput = document.getElementById("deploy-name-input");
  const hint = document.getElementById("deploy-count-hint");
  const submitBtn = document.getElementById("btn-submit-deploy");
  const count = parseInt(countInput?.value || "1");
  const baseName = (nameInput?.value || "node-01").trim();

  if (count <= 1) {
    if (hint) hint.textContent = "Deploy 1 instance";
    if (submitBtn && submitBtn.querySelector("span")) submitBtn.querySelector("span").textContent = "Deploy Instance";
  } else {
    let p1 = baseName, p2 = baseName;
    if (baseName.match(/-\d+$/)) {
      const pfx = baseName.replace(/-\d+$/, "");
      p1 = `${pfx}-01`;
      p2 = count >= 10 ? `${pfx}-${String(count).padStart(2, '0')}` : `${pfx}-${count}`;
    } else {
      p1 = `${baseName}-01`;
      p2 = count >= 10 ? `${baseName}-${String(count).padStart(2, '0')}` : `${baseName}-${count}`;
    }
    if (hint) hint.textContent = `Batch (${count}): ${p1} ... ${p2}`;
    if (submitBtn && submitBtn.querySelector("span")) submitBtn.querySelector("span").textContent = `Deploy ${count} Instances`;
  }
}
window.updateDeployCountPreview = updateDeployCountPreview;

function openLinodeSwapModal() {
  if (!currentServerModal || !currentServerModal.server) return;
  const s = currentServerModal.server;
  const accId = s.account_id || currentServerModalAccId;
  const peerLinodes = state.servers.filter(x => x.account_id === accId && String(x.id) !== String(s.id) && x.region === s.region);
  if (peerLinodes.length === 0) {
    showToast(`No other Linodes found in datacenter ${s.region} on this account to swap IPs with.`, "warning");
    return;
  }
  document.getElementById("linode-swap-current-srv").textContent = `${s.name || s.label} (${s.ip}) — [${s.region}]`;
  const sel = document.getElementById("linode-swap-target-select");
  sel.innerHTML = `<option value="">Select regional peer Linode...</option>` +
    peerLinodes.map(p => `<option value="${p.id}">${escapeHtml(p.name || p.label || p.id)} (${p.ip || 'no-ip'}) [${p.region}]</option>`).join("");
  openModal("modal-linode-swap-ip");
}
window.openLinodeSwapModal = openLinodeSwapModal;

async function submitLinodeSwap(e) {
  if (e) e.preventDefault();
  if (!currentServerModal || !currentServerModal.server) return;
  const s = currentServerModal.server;
  const accId = s.account_id || currentServerModalAccId;
  const targetId = document.getElementById("linode-swap-target-select").value;
  if (!targetId) {
    showToast("Please select a target Linode to swap with.", "warning");
    return;
  }
  const targetSrv = state.servers.find(x => String(x.id) === String(targetId));
  const targetName = targetSrv ? (targetSrv.name || targetSrv.label || targetId) : targetId;

  confirmAction(`Swap public IPv4 address of ${s.name || s.label} (${s.ip}) with ${targetName} (${targetSrv?.ip})?`, "SWAP_LINODE_IPS", async () => {
    try {
      await api("swap_linode_ips", {
        account_id: accId,
        server_id: s.id,
        target_server_id: targetId,
        confirm: "SWAP_LINODE_IPS"
      });
      showToast("Linode IPv4 addresses swapped successfully!", "success");
      closeModal("modal-linode-swap-ip");
      refreshCurrentServerDetailsModal();
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}
window.submitLinodeSwap = submitLinodeSwap;
window.navigateFromModalToAccount = navigateFromModalToAccount;

// ==================== FORM HANDLERS ====================
function initForms() {
  // Deployment account changed -> fetch regions
  const deployAccSel = document.getElementById("deploy-account-select");
  deployAccSel.addEventListener("change", async () => {
    const accId = deployAccSel.value;
    if (!accId) {
      resetDeploySelectors();
      return;
    }

    const acc = state.accounts.find(a => a.id === parseInt(accId));
    const hetznerOpts = document.getElementById("deploy-hetzner-options");
    if (hetznerOpts) {
      hetznerOpts.style.display = (acc && acc.provider === "hetzner") ? "block" : "none";
      const v6Cb = document.getElementById("deploy-enable-ipv6");
      if (v6Cb) v6Cb.checked = false;
    }
    const regSel = document.getElementById("deploy-region-select");
    const imgSel = document.getElementById("deploy-image-select");

    // Instant population if regions cached
    if (state.regionsCache[accId]) {
      const regions = state.regionsCache[accId];
      regSel.innerHTML = `<option value="">Choose region...</option>` +
        regions.map(r => `<option value="${r.id}">${escapeHtml(r.label || r.id)}</option>`).join("");
      regSel.disabled = false;
      const acc = state.accounts.find(a => a.id === parseInt(accId));
      if (acc && acc.region && regions.some(r => r.id === acc.region)) {
        regSel.value = acc.region;
        regSel.dispatchEvent(new Event("change"));
      }
    } else {
      regSel.disabled = true;
      regSel.innerHTML = `<option value="">Loading regions...</option>`;
      try {
        const regions = await getCachedRegions(accId);
        regSel.innerHTML = `<option value="">Choose region...</option>` +
          regions.map(r => `<option value="${r.id}">${escapeHtml(r.label || r.id)}</option>`).join("");
        regSel.disabled = false;
        const acc = state.accounts.find(a => a.id === parseInt(accId));
        if (acc && acc.region && regions.some(r => r.id === acc.region)) {
          regSel.value = acc.region;
          regSel.dispatchEvent(new Event("change"));
        }
      } catch (e) {
        regSel.innerHTML = `<option value="">Failed loading regions</option>`;
      }
    }

    // Instant population if images cached
    if (state.imagesCache[accId]) {
      const images = state.imagesCache[accId];
      imgSel.innerHTML = `<option value="">Choose image...</option>` +
        images.map(i => `<option value="${i.id}">${escapeHtml(i.label || i.id)}</option>`).join("");
      imgSel.disabled = false;
    } else {
      getCachedImages(accId).then(images => {
        if (deployAccSel.value === accId) {
          imgSel.innerHTML = `<option value="">Choose image...</option>` +
            images.map(i => `<option value="${i.id}">${escapeHtml(i.label || i.id)}</option>`).join("");
          imgSel.disabled = false;
        }
      }).catch(() => {});
    }
  });

  // Deployment region changed -> fetch plans and images
  const deployRegSel = document.getElementById("deploy-region-select");
  deployRegSel.addEventListener("change", async () => {
    const accId = parseInt(deployAccSel.value);
    const region = deployRegSel.value;
    if (!region || !accId) return;

    const planSel = document.getElementById("deploy-plan-select");
    const imgSel = document.getElementById("deploy-image-select");
    const cacheKey = `${accId}:${region}`;

    // If cached plans exist, populate IMMEDIATELY (zero delay/wait!)
    if (state.plansCache[cacheKey]) {
      const plans = state.plansCache[cacheKey];
      planSel.innerHTML = `<option value="">Choose plan...</option>` +
        plans.map(p => `<option value="${p.id}">${escapeHtml(p.label || p.id)}</option>`).join("");
      planSel.disabled = false;
    } else {
      planSel.disabled = true;
      planSel.innerHTML = `<option value="">Loading plans...</option>`;
      try {
        const plans = await getCachedPlans(accId, region);
        if (deployRegSel.value === region) {
          planSel.innerHTML = `<option value="">Choose plan...</option>` +
            plans.map(p => `<option value="${p.id}">${escapeHtml(p.label || p.id)}</option>`).join("");
          planSel.disabled = false;
        }
      } catch (e) {
        showToast("Error loading plans", "error");
        planSel.innerHTML = `<option value="">Failed loading plans</option>`;
      }
    }

    // Ensure images are populated
    if (state.imagesCache[accId]) {
      const images = state.imagesCache[accId];
      imgSel.innerHTML = `<option value="">Choose image...</option>` +
        images.map(i => `<option value="${i.id}">${escapeHtml(i.label || i.id)}</option>`).join("");
      imgSel.disabled = false;
    } else if (imgSel.options.length <= 1) {
      imgSel.disabled = true;
      imgSel.innerHTML = `<option value="">Loading OS images...</option>`;
      try {
        const images = await getCachedImages(accId);
        imgSel.innerHTML = `<option value="">Choose image...</option>` +
          images.map(i => `<option value="${i.id}">${escapeHtml(i.label || i.id)}</option>`).join("");
        imgSel.disabled = false;
      } catch (e) {
        imgSel.innerHTML = `<option value="">Failed loading images</option>`;
      }
    }
  });

  // Allocate IP account select change listener
  const allocAccSel = document.getElementById("alloc-account-select");
  if (allocAccSel) {
    allocAccSel.addEventListener("change", () => {
      updateAllocIpAccountServers(allocAccSel.value);
    });
  }
  const allocSrvSel = document.getElementById("alloc-server-select");
  if (allocSrvSel) {
    allocSrvSel.addEventListener("change", () => {
      const accId = document.getElementById("alloc-account-select").value;
      const acc = state.accounts.find(a => a.id === parseInt(accId));
      const locWrap = document.getElementById("alloc-location-wrap");
      if (locWrap) {
        if (acc && acc.provider === "hetzner" && !allocSrvSel.value) {
          locWrap.style.display = "";
        } else {
          locWrap.style.display = "none";
        }
      }
    });
  }

  // Deploy server submit
  document.getElementById("form-deploy-server").addEventListener("submit", async (e) => {
    e.preventDefault();
    const accId = parseInt(deployAccSel.value);
    const region = deployRegSel.value;
    const plan = document.getElementById("deploy-plan-select").value;
    const image = document.getElementById("deploy-image-select").value;
    const name = document.getElementById("deploy-name-input").value.trim();
    const sshKeyId = document.getElementById("deploy-ssh-select").value;
    const count = parseInt(document.getElementById("deploy-count-input")?.value || "1");
    const enableIpv6 = !!document.getElementById("deploy-enable-ipv6")?.checked;

    const submitBtn = document.getElementById("btn-submit-deploy");
    const loadingText = count > 1 ? `Deploying ${count} instances...` : "Deploying instance...";

    await runWithButtonLoading(submitBtn, async () => {
      try {
        const args = {
          account_id: accId,
          region,
          plan,
          image,
          name,
          count,
          enable_ipv6: enableIpv6,
          confirm: "CREATE_SERVER"
        };
        if (sshKeyId) {
          args.ssh_key_ids = [parseInt(sshKeyId)];
        } else if (state.sshKeys.length > 0) {
          args.ssh_key_ids = state.sshKeys.map(k => k.id);
        }

        const res = await api("create_server", args);
        if (res.created_count && res.created_count > 1) {
          showToast(`Successfully deployed ${res.created_count} instances in batch!`, "success");
        } else {
          showToast(`Server ${res.server ? res.server.label || res.server.id : name} deployed successfully!`, "success");
        }
        closeModal("modal-deploy-server");
        loadAll();
      } catch (err) {
        showToast(err.message, "error");
      } finally {
        updateDeployCountPreview();
      }
    }, loadingText);
  });

  // Allocate IP submit
  document.getElementById("form-alloc-ip").addEventListener("submit", async (e) => {
    e.preventDefault();
    const accId = parseInt(document.getElementById("alloc-account-select").value);
    const ipType = document.getElementById("alloc-type-select").value;
    const srvId = document.getElementById("alloc-server-select").value || null;
    const loc = document.getElementById("alloc-location-select").value || "fsn1";

    const submitBtn = document.getElementById("btn-submit-alloc-ip");
    const cancelBtn = document.getElementById("btn-cancel-alloc-ip");
    const formFields = document.getElementById("alloc-form-fields");
    const progressBox = document.getElementById("alloc-progress");
    const successBox = document.getElementById("alloc-success");
    const progressMsg = document.getElementById("alloc-progress-msg");
    const footer = document.getElementById("alloc-footer");

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = `<span class="btn-spinner"></span> Allocating IP...`;
    }
    if (cancelBtn) cancelBtn.disabled = true;
    if (formFields) formFields.style.display = "none";
    if (progressBox) progressBox.style.display = "";
    if (progressMsg) progressMsg.textContent = "🌐 Contacting cloud provider...";

    const progressTimer = setTimeout(() => {
      if (progressMsg) progressMsg.textContent = "Configuring floating IP routing...";
    }, 600);

    try {
      const res = await api("create_floating_ip", {
        account_id: accId,
        ip_type: ipType,
        server_id: srvId,
        home_location: loc,
        confirm: "CREATE_FLOATING_IP"
      });
      clearTimeout(progressTimer);

      const fip = res.floating_ip || {};
      const fipVal = fip.ip || fip.ip_address || fip.subnet || fip.network || 'Allocated IP';
      const isV6 = (fip.type === 'ipv6' || ipType === 'ipv6');
      const osCmd = isV6 ? `ip -6 addr add ${fipVal}/64 dev eth0` : `ip addr add ${fipVal}/32 dev eth0`;
      const acc = state.accounts.find(a => a.id === accId);
      const srv = srvId ? state.servers.find(s => s.account_id === accId && String(s.id) === String(srvId)) : null;

      showToast("Floating IP allocated successfully!", "success");
      loadAll();

      if (progressBox) progressBox.style.display = "none";
      if (footer) footer.style.display = "none";
      if (successBox) {
        successBox.style.display = "";
        successBox.innerHTML = `
          <div class="p-4 text-center">
            <div class="inline-flex items-center justify-center w-12 h-12 rounded-full mb-2" style="background: rgba(16, 185, 129, 0.15); font-size: 1.5rem;">✅</div>
            <h4 class="text-base font-bold text-primary">Floating IP Allocated Successfully!</h4>
            <p class="text-xs text-secondary mt-1">
              ${srv ? `Attached directly to <strong class="text-primary">${escapeHtml(srv.name || srv.label || srvId)}</strong>` : `Allocated to <strong class="text-primary">${escapeHtml(acc?.label || 'account')}</strong> pool`}
            </p>

            <div class="my-4 p-3 bg-surface rounded-md border border-subtle flex items-center justify-between gap-3">
              <div class="text-left">
                <div class="text-xs text-secondary font-medium">Allocated Floating IP</div>
                <code class="font-mono text-lg font-bold text-primary">${escapeHtml(fipVal)}</code>
              </div>
              <button type="button" class="btn btn-sm btn-secondary" onclick="copyText('${escapeHtml(fipVal)}')">📋 Copy IP</button>
            </div>

            ${(srvId || acc?.provider === 'hetzner') ? `
              <div class="p-3 bg-surface rounded-md border border-subtle text-left mb-4">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs text-secondary font-medium">Guest OS Activation (eth0)</span>
                  <button type="button" class="btn btn-xs btn-secondary" onclick="copyText('${osCmd}')">Copy Command</button>
                </div>
                <code class="font-mono text-xs text-primary block break-all bg-black p-2 rounded">${osCmd}</code>
                <div class="text-xs text-muted mt-1.5">Run with root privileges on the server to activate traffic routing immediately.</div>
              </div>
            ` : ''}

            <div class="flex items-center justify-center gap-2 pt-2">
              <button type="button" class="btn btn-secondary btn-sm" onclick="closeModal('modal-alloc-ip')">Close</button>
              ${srvId ? `<button type="button" class="btn btn-primary btn-sm" onclick="closeModal('modal-alloc-ip'); openServerDetailsModal(${accId}, '${srvId}');">🖥️ View Server Details</button>` : ''}
            </div>
          </div>
        `;
      }
    } catch (err) {
      clearTimeout(progressTimer);
      showToast(err.message, "error");
      if (progressBox) progressBox.style.display = "none";
      if (formFields) formFields.style.display = "";
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = "<span>Allocate IP</span>";
      }
      if (cancelBtn) cancelBtn.disabled = false;
    }
  });

  // Attach Floating IP submit
  document.getElementById("form-attach-fip").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fipId = document.getElementById("attach-fip-id").value;
    const accId = parseInt(document.getElementById("attach-fip-acc-id").value);
    const serverId = document.getElementById("attach-target-server-select").value;
    const submitBtn = document.getElementById("btn-submit-attach-fip");

    await runWithButtonLoading(submitBtn, async () => {
      try {
        await api("assign_floating_ip", {
          account_id: accId,
          floating_id: fipId,
          server_id: serverId
        });
        showToast("Floating IP attached successfully!", "success");
        closeModal("modal-attach-fip");
        loadAll();
      } catch (err) {
        showToast(err.message, "error");
      }
    }, "Attaching IP...");
  });

  // Add SSH Key submit
  document.getElementById("form-add-ssh").addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = document.getElementById("ssh-key-name").value.trim();
    const pubKey = document.getElementById("ssh-public-key").value.trim();
    const sync = document.getElementById("ssh-sync-providers").checked;
    const submitBtn = document.getElementById("btn-submit-add-ssh");

    await runWithButtonLoading(submitBtn, async () => {
      try {
        await api("add_ssh_key", {
          name,
          public_key: pubKey,
          sync_accounts: sync
        });
        showToast("SSH key added to vault!", "success");
        closeModal("modal-add-ssh");
        loadAll();
      } catch (err) {
        showToast(err.message, "error");
      }
    }, "Saving Key...");
  });

  // Add Account submit
  document.getElementById("form-add-account").addEventListener("submit", async (e) => {
    e.preventDefault();
    const provider = document.getElementById("acc-provider").value;
    const label = document.getElementById("acc-label").value.trim();
    const token = document.getElementById("acc-token").value.trim();
    const regionEl = document.getElementById("acc-region");
    const region = regionEl ? normalizeCountryCode(regionEl.value) : "";

    const proxyType = document.querySelector('input[name="add-acc-proxy-type"]:checked')?.value || "none";
    let proxy = null;
    let proxyProviderId = null;

    if (proxyType === "custom") {
      proxy = document.getElementById("acc-proxy")?.value.trim() || null;
    } else if (proxyType === "pool") {
      if (!region) {
        showToast("Account Region is required to allocate a proxy from providers.", "error");
        if (regionEl) regionEl.focus();
        return;
      }
      proxyProviderId = document.getElementById("add-acc-proxy-provider-select")?.value || "auto";
    }

    const submitBtn = document.getElementById("btn-submit-add-acc");
    await runWithButtonLoading(submitBtn, async () => {
      try {
        const payload = { provider, label, token, region };
        if (proxyType === "custom") {
          payload.proxy = proxy;
        } else if (proxyType === "pool") {
          payload.proxy_provider_id = proxyProviderId;
        }
        const res = await api("add_account", payload);
        let msg = `Account ${label} added successfully!`;
        if (res.allocated_proxy) {
          msg += ` Allocated proxy for ${getCountryFlag(res.allocated_proxy.country || region)} ${res.allocated_proxy.country || region}.`;
        }
        showToast(msg, "success");
        closeModal("modal-add-account");
        loadAll();
      } catch (err) {
        showToast(err.message, "error");
      }
    }, "Connecting & Verifying...");
  });

  // Handle Linode Promo Code Submit
  const formLinodePromo = document.getElementById("form-linode-promo");
  if (formLinodePromo) {
    formLinodePromo.addEventListener("submit", async (e) => {
      e.preventDefault();
      const accId = parseInt(document.getElementById("linode-promo-acc-id")?.value);
      const codeInput = document.getElementById("linode-promo-code-input");
      const code = (codeInput?.value || "").trim().toUpperCase();
      const btn = document.getElementById("btn-submit-linode-promo");
      const resEl = document.getElementById("linode-promo-result");

      if (!code || !accId) return;
      if (resEl) {
        resEl.className = "mt-3 p-3 bg-card border rounded text-xs text-secondary";
        resEl.innerHTML = "⏳ Applying promo code to Linode account...";
      }

      await runWithButtonLoading(btn, async () => {
        try {
          const res = await api("apply_promo_code", { account_id: accId, promo_code: code });
          const p = res.promotion || {};
          const credit = p.credit_remaining || p.credit_monthly_cap || "Applied";
          const summary = p.summary || p.description || "Promotional credit added successfully!";
          const expire = p.expire_dt || "—";
          showToast(`🎉 Promo code applied! Credit: $${credit}`, "success");
          if (resEl) {
            resEl.className = "mt-3 p-3 bg-card border border-success rounded text-xs";
            resEl.innerHTML = `
              <div class="text-success font-bold mb-1">✅ Promo Code Applied Successfully!</div>
              <div><strong>Credit:</strong> $${escapeHtml(String(credit))}</div>
              <div><strong>Summary:</strong> ${escapeHtml(String(summary))}</div>
              <div><strong>Expires:</strong> <code>${escapeHtml(String(expire))}</code></div>
            `;
          }
          refreshSingleAccountBilling(accId);
        } catch (err) {
          showToast(`Failed: ${err.message}`, "error");
          if (resEl) {
            resEl.className = "mt-3 p-3 bg-card border border-danger rounded text-xs text-danger";
            resEl.innerHTML = `❌ <strong>Error:</strong> ${escapeHtml(err.message)}`;
          }
        }
      }, "Applying Promo...");
    });
  }

  // Handle Rotating Proxy Pool Session Allocation
  const formPoolAssign = document.getElementById("form-proxy-pool-assign");
  if (formPoolAssign) {
    formPoolAssign.addEventListener("submit", async (e) => {
      e.preventDefault();
      const accId = parseInt(document.getElementById("edit-proxy-account-id").value);
      const provSelect = document.getElementById("pool-assign-provider");
      const ctrySelect = document.getElementById("pool-assign-country");
      const pid = parseInt(provSelect ? provSelect.value : 0);
      const ctry = normalizeCountryCode(ctrySelect ? ctrySelect.value : "");
      const btn = document.getElementById("btn-submit-pool-assign");

      if (!pid) {
        showToast("Please select or add a rotating proxy pool first.", "error");
        return;
      }

      await runWithButtonLoading(btn, async () => {
        try {
          const res = await api("allocate_account_proxy", {
            account_id: accId,
            provider_id: pid,
            country: ctry
          });
          showToast(`Proxy allocated and bound to ${ctry} successfully!`, "success");
          closeModal("modal-edit-proxy");
          const accIdx = state.accounts.findIndex(a => a.id === accId);
          if (accIdx >= 0 && res.account) {
            state.accounts[accIdx] = res.account;
          }
          renderAccountsManagement();
          renderProxyManagement();
          renderOverview();
          refreshSingleAccountBilling(accId);
        } catch (err) {
          showToast(err.message, "error");
        }
      }, "Allocating Session...");
    });
  }

  // Check Pool Availability
  const btnCheckAvail = document.getElementById("btn-check-pool-avail");
  if (btnCheckAvail) {
    btnCheckAvail.addEventListener("click", async () => {
      const pid = parseInt(document.getElementById("pool-assign-provider").value);
      const ctry = normalizeCountryCode(document.getElementById("pool-assign-country").value);
      const statusBox = document.getElementById("pool-avail-status");
      if (!pid || !ctry) return;
      if (statusBox) statusBox.textContent = `Checking ${ctry} availability in pool...`;

      await runWithButtonLoading(btnCheckAvail, async () => {
        try {
          const res = await api("proxy_availability", { provider_id: pid, country: ctry });
          if (statusBox) statusBox.innerHTML = `<span class="text-success font-bold">✓ ${res.available} session(s) available</span> for ${ctry}.`;
        } catch (err) {
          if (statusBox) statusBox.innerHTML = `<span class="text-danger">Failed to check: ${escapeHtml(err.message)}</span>`;
        }
      }, "Checking...");
    });
  }

  // Handle Custom Proxy Save
  const formCustomProxy = document.getElementById("form-proxy-custom-assign");
  if (formCustomProxy) {
    formCustomProxy.addEventListener("submit", async (e) => {
      e.preventDefault();
      const accId = parseInt(document.getElementById("edit-proxy-account-id").value);
      const proxyVal = document.getElementById("custom-proxy-input").value.trim();
      const family = document.getElementById("custom-proxy-family").value;
      const regionVal = normalizeCountryCode(document.getElementById("custom-proxy-region").value);
      const btn = document.getElementById("btn-submit-custom-proxy");

      await runWithButtonLoading(btn, async () => {
        try {
          const res = await api("set_account_proxy", {
            account_id: accId,
            proxy: proxyVal || null,
            proxy_family: family,
            region: regionVal
          });
          showToast("Custom proxy configuration saved!", "success");
          closeModal("modal-edit-proxy");
          const accIdx = state.accounts.findIndex(a => a.id === accId);
          if (accIdx >= 0 && res.account) {
            state.accounts[accIdx] = res.account;
          }
          renderAccountsManagement();
          renderProxyManagement();
          renderOverview();
          refreshSingleAccountBilling(accId);
        } catch (err) {
          showToast(err.message, "error");
        }
      }, "Saving Proxy...");
    });
  }

  // Verify Custom Proxy
  const btnVerifyCustom = document.getElementById("btn-verify-custom-proxy");
  if (btnVerifyCustom) {
    btnVerifyCustom.addEventListener("click", async () => {
      const proxyVal = document.getElementById("custom-proxy-input").value.trim();
      const resBox = document.getElementById("custom-proxy-test-result");
      if (!proxyVal) {
        if (resBox) resBox.innerHTML = `<span class="text-warning">Please enter a proxy string to test.</span>`;
        return;
      }
      if (resBox) {
        resBox.className = "text-xs font-mono text-secondary mt-2";
        resBox.textContent = "Connecting through proxy...";
      }

      await runWithButtonLoading(btnVerifyCustom, async () => {
        try {
          const res = await api("test_proxy", { proxy: proxyVal });
          if (res.status === "ok") {
            if (resBox) {
              resBox.className = "text-xs font-mono text-success mt-2";
              resBox.textContent = `✅ Connection successful! Egress IP: ${res.ip} (Latency: ${res.latency_ms}ms)`;
            }
          } else {
            if (resBox) {
              resBox.className = "text-xs font-mono text-danger mt-2";
              resBox.textContent = `❌ Verification failed: ${res.error}`;
            }
          }
        } catch (err) {
          if (resBox) {
            resBox.className = "text-xs font-mono text-danger mt-2";
            resBox.textContent = `❌ Error: ${err.message}`;
          }
        }
      }, "Testing...");
    });
  }

  // Clear Proxy (Direct connection)
  const btnClearProxy = document.getElementById("btn-submit-clear-proxy");
  if (btnClearProxy) {
    btnClearProxy.addEventListener("click", async () => {
      const accId = parseInt(document.getElementById("edit-proxy-account-id").value);
      await runWithButtonLoading(btnClearProxy, async () => {
        try {
          const res = await api("set_account_proxy", { account_id: accId, proxy: "" });
          showToast("Proxy removed; account will route directly.", "info");
          closeModal("modal-edit-proxy");
          const accIdx = state.accounts.findIndex(a => a.id === accId);
          if (accIdx >= 0 && res.account) {
            state.accounts[accIdx] = res.account;
          }
          renderAccountsManagement();
          renderProxyManagement();
          renderOverview();
          refreshSingleAccountBilling(accId);
        } catch (err) {
          showToast(err.message, "error");
        }
      }, "Disconnecting...");
    });
  }

  // Handle Edit Account Region Save
  const formEditRegion = document.getElementById("form-edit-account-region");
  if (formEditRegion) {
    formEditRegion.addEventListener("submit", async (e) => {
      e.preventDefault();
      const accId = parseInt(document.getElementById("edit-region-account-id").value);
      const regVal = normalizeCountryCode(document.getElementById("edit-region-select").value);
      const btn = document.getElementById("btn-save-account-region");

      await runWithButtonLoading(btn, async () => {
        try {
          const res = await api("set_account_region", { account_id: accId, region: regVal });
          showToast(`Account region saved to ${regVal}!`, "success");
          closeModal("modal-edit-region");
          const accIdx = state.accounts.findIndex(a => a.id === accId);
          if (accIdx >= 0 && res.account) {
            state.accounts[accIdx] = res.account;
          }
          renderAccountsManagement();
        } catch (err) {
          showToast(err.message, "error");
        }
      }, "Saving Region...");
    });
  }

  // Add Proxy Provider submit
  const formAddProxyProv = document.getElementById("form-add-proxy-provider");
  if (formAddProxyProv) {
    formAddProxyProv.addEventListener("submit", async (e) => {
      e.preventDefault();
      const label = document.getElementById("proxy-provider-label").value.trim();
      let template = "";
      let scheme = "http";

      if (activeProxyCreationMode === 'builder') {
        scheme = document.getElementById("builder-proxy-scheme").value || "http";
        const host = document.getElementById("builder-proxy-host").value.trim();
        const port = document.getElementById("builder-proxy-port").value.trim() || "80";
        const user = document.getElementById("builder-proxy-user").value.trim();
        const pass = document.getElementById("builder-proxy-pass").value.trim();

        if (!host) {
          showToast("Please enter proxy host or gateway", "error");
          return;
        }
        if (!user || !user.includes("{country}") || !user.includes("{session}")) {
          showToast("Username pattern must contain both {country} and {session} tokens", "error");
          return;
        }
        template = {
          scheme,
          host,
          port: parseInt(port, 10),
          username: user,
          password: pass,
          auth: !!(user || pass)
        };
      } else if (activeProxyCreationMode === 'url') {
        template = document.getElementById("proxy-provider-template").value.trim();
        if (!template) {
          showToast("Please enter a proxy template URL", "error");
          return;
        }
      } else if (activeProxyCreationMode === 'sample') {
        const rawSample = document.getElementById("proxy-sample-lines-input").value.trim();
        if (!rawSample) {
          showToast("Please paste sample proxy lines", "error");
          return;
        }
        template = rawSample.split("\n")[0].trim();
      }

      const sessions = document.getElementById("proxy-provider-sessions").value.trim();
      const family = document.getElementById("proxy-provider-family").value;
      const btn = document.getElementById("btn-submit-add-proxy-provider");

      await runWithButtonLoading(btn, async () => {
        try {
          await api("add_proxy_provider", {
            label,
            template,
            session_ids: sessions,
            scheme,
            family
          });
          showToast(`Proxy provider "${label}" created successfully!`, "success");
          closeModal("modal-add-proxy-provider");
          const res = await api("proxy_providers");
          state.proxyProviders = res.providers || [];
          renderProxyManagement();
          updateBadges();
        } catch (err) {
          showToast(err.message, "error");
        }
      }, "Creating Pool...");
    });
  }

  // Quick Test Proxy submit
  const formQuickTestProxy = document.getElementById("form-quick-test-proxy");
  if (formQuickTestProxy) {
    formQuickTestProxy.addEventListener("submit", async (e) => {
      e.preventDefault();
      const inputEl = document.getElementById("test-proxy-string-input");
      let raw = inputEl.value.trim();
      const targetAccId = inputEl.getAttribute("data-account-id");
      const scheme = document.getElementById("test-proxy-scheme")?.value || "auto";
      const badge = document.getElementById("test-proxy-status-badge");
      const details = document.getElementById("test-proxy-details");
      const btn = document.getElementById("btn-run-proxy-test");

      if (!targetAccId && scheme !== "auto" && !raw.includes("://")) {
        raw = `${scheme}://${raw}`;
      }

      if (badge) { badge.className = "badge"; badge.textContent = "Testing..."; }
      if (details) { details.textContent = "Testing proxy tunnel and measuring latency..."; }

      await runWithButtonLoading(btn, async () => {
        try {
          const payload = targetAccId ? { account_id: parseInt(targetAccId, 10) } : { proxy: raw };
          const res = await api("test_proxy", payload);
          if (res.status === "ok") {
            if (badge) { badge.className = "badge badge-status-running"; badge.textContent = "Connected"; }
            if (details) {
              details.innerHTML = `<span class="text-success font-bold">Success!</span> Egress Public IP: <code class="text-primary font-bold">${res.ip}</code><br>Round-trip Latency: <span class="text-success font-bold">${res.latency_ms}ms</span>`;
            }
          } else {
            if (badge) { badge.className = "badge badge-status-off"; badge.textContent = "Failed"; }
            if (details) { details.textContent = `Error: ${res.error}`; }
          }
        } catch (err) {
          if (badge) { badge.className = "badge badge-status-off"; badge.textContent = "Error"; }
          if (details) { details.textContent = err.message; }
        }
      }, "Running Diagnostic...");
    });
  }

  // Edit Proxy Provider submit
  const formEditProxyProv = document.getElementById("form-edit-proxy-provider");
  if (formEditProxyProv) {
    formEditProxyProv.addEventListener("submit", async (e) => {
      e.preventDefault();
      const pid = parseInt(document.getElementById("edit-proxy-provider-id").value, 10);
      const label = document.getElementById("edit-proxy-provider-label").value.trim();
      const template = document.getElementById("edit-proxy-provider-template").value.trim();
      const btn = document.getElementById("btn-save-proxy-provider");

      await runWithButtonLoading(btn, async () => {
        try {
          const payload = { provider_id: pid, label };
          if (template) payload.template = template;
          await api("update_proxy_provider", payload);
          showToast("Proxy provider updated successfully!", "success");
          closeModal("modal-edit-proxy-provider");
          const res = await api("proxy_providers");
          state.proxyProviders = res.providers || [];
          renderProxyManagement();
        } catch (err) {
          showToast(err.message, "error");
        }
      }, "Saving Changes...");
    });
  }

  // Quick add session on Enter key
  const quickAddInput = document.getElementById("input-quick-add-session");
  if (quickAddInput) {
    quickAddInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submitQuickAddSession();
      }
    });
  }

  // Ed25519 WebCrypto Keypair Generator
  const btnGenKey = document.getElementById("btn-run-generate-key");
  if (btnGenKey) {
    btnGenKey.addEventListener("click", async () => {
      const keyName = document.getElementById("gen-key-name").value.trim() || "generated-ed25519-key";
      await runWithButtonLoading(btnGenKey, async () => {
        try {
          const keyPair = await window.crypto.subtle.generateKey(
            { name: "Ed25519" },
            true,
            ["sign", "verify"]
          );

          const rawPub = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
          const pubBytes = new Uint8Array(rawPub);
          const header = new Uint8Array([0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32]);
          const fullPub = new Uint8Array(header.length + pubBytes.length);
          fullPub.set(header, 0);
          fullPub.set(pubBytes, header.length);
          const pubBase64 = btoa(String.fromCharCode.apply(null, fullPub));
          const opensshPub = `ssh-ed25519 ${pubBase64} ${keyName}`;

          const rawPriv = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
          const privBase64 = btoa(String.fromCharCode.apply(null, new Uint8Array(rawPriv)));
          const pemPriv = `-----BEGIN PRIVATE KEY-----\n${privBase64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;

          // Save to vault automatically
          await api("add_ssh_key", { name: keyName, public_key: opensshPub, sync_accounts: true });

          document.getElementById("gen-public-key").textContent = opensshPub;
          document.getElementById("gen-key-results").classList.remove("hidden");

          document.getElementById("btn-download-privkey").onclick = () => {
            downloadFile(`${keyName}.pem`, pemPriv);
          };

          showToast("Ed25519 keypair generated and saved to vault!", "success");
          loadAll();
        } catch (err) {
          showToast("WebCrypto generation failed: " + err.message, "error");
        }
      }, "Generating...");
    });
  }

  // Live 2-Letter Country Code / Flag Preview Listeners
  const editRegInput = document.getElementById("edit-region-select");
  if (editRegInput) {
    editRegInput.addEventListener("input", (e) => {
      e.target.value = e.target.value.toUpperCase();
      updateEditRegionPreview(e.target.value);
    });
  }

  const poolCountryInput = document.getElementById("pool-assign-country");
  if (poolCountryInput) {
    poolCountryInput.addEventListener("input", (e) => {
      e.target.value = e.target.value.toUpperCase();
      updatePoolCountryPreview(e.target.value);
    });
  }

  const customProxyRegInput = document.getElementById("custom-proxy-region");
  if (customProxyRegInput) {
    customProxyRegInput.addEventListener("input", (e) => {
      e.target.value = e.target.value.toUpperCase();
      updateCustomProxyPreview(e.target.value);
    });
  }

  const accRegInput = document.getElementById("acc-region");
  if (accRegInput) {
    accRegInput.addEventListener("input", (e) => {
      e.target.value = e.target.value.toUpperCase();
      const flagEl = document.getElementById("add-acc-flag-preview");
      if (flagEl) flagEl.textContent = getCountryFlag(e.target.value);
    });
  }

  // Bulk Sessions Live Parser
  const bulkInput = document.getElementById("bulk-sessions-input");
  if (bulkInput) {
    bulkInput.addEventListener("input", (e) => {
      updateBulkSessionsPreview(e.target.value);
    });
  }

  const bulkProvSelect = document.getElementById("bulk-sessions-provider");
  if (bulkProvSelect) {
    bulkProvSelect.addEventListener("change", () => {
      const val = document.getElementById("bulk-sessions-input")?.value || "";
      updateBulkSessionsPreview(val);
    });
  }

  // Form: Bulk Import Sessions
  const formBulkSessions = document.getElementById("form-add-proxy-sessions");
  if (formBulkSessions) {
    formBulkSessions.addEventListener("submit", async (e) => {
      e.preventDefault();
      const pid = parseInt(document.getElementById("bulk-sessions-provider").value);
      const rawText = document.getElementById("bulk-sessions-input").value;
      const btn = document.getElementById("btn-submit-bulk-sessions");
      if (!pid) {
        showToast("Please select a target proxy provider pool", "error");
        return;
      }
      if (!rawText.trim()) {
        showToast("Please enter or paste proxy lines / session IDs", "error");
        return;
      }

      await runWithButtonLoading(btn, async () => {
        try {
          const res = await api("add_proxy_sessions", { provider_id: pid, raw_text: rawText });
          showToast(`🎉 Added ${res.added} session(s) to pool! (Total: ${res.total_sessions})`, "success");
          closeModal("modal-add-proxy-sessions");
          const provRes = await api("proxy_providers");
          state.proxyProviders = provRes.providers || [];
          renderProxyManagement();
          updateBadges();
        } catch (err) {
          showToast(`Import failed: ${err.message}`, "error");
        }
      }, "Importing Sessions...");
    });
  }

  // Auto-heal and bulk session trigger buttons
  const btnHealAccs = document.getElementById("btn-auto-heal-accounts");
  if (btnHealAccs) btnHealAccs.addEventListener("click", runAutoHealProxies);

  const btnHealProxies = document.getElementById("btn-auto-heal-proxies");
  if (btnHealProxies) btnHealProxies.addEventListener("click", runAutoHealProxies);

  const btnBulkImport = document.getElementById("btn-bulk-import-sessions");
  if (btnBulkImport) btnBulkImport.addEventListener("click", () => openBulkSessionsModal());
}

// ==================== ACTIONS ====================
async function powerServer(accId, serverId, action) {
  const confirmStr = action.toUpperCase();
  confirmAction(`Are you sure you want to ${action} instance #${serverId}?`, confirmStr, async () => {
    try {
      await api("power_server", {
        account_id: accId,
        server_id: serverId,
        action,
        confirm: confirmStr
      });
      showToast(`Power command '${action}' sent.`, "success");
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

async function showServerPassword(accId, serverId) {
  confirmAction("Reveal root password for this server from secure secrets vault?", "SHOW_PASSWORD", async () => {
    try {
      const res = await api("server_password", {
        account_id: accId,
        server_id: serverId,
        confirm: "SHOW_PASSWORD"
      });
      document.getElementById("revealed-password-text").textContent = res.password || "Password not stored";
      openModal("modal-show-password");
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

async function deleteServer(accId, serverId, serverLabel) {
  confirmAction(`Permanently delete instance '${serverLabel}'? All data will be destroyed!`, "DELETE_SERVER", async () => {
    try {
      await api("delete_server", {
        account_id: accId,
        server_id: serverId,
        confirm: "DELETE_SERVER"
      });
      showToast(`Instance ${serverLabel} deleted.`, "success");
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

async function checkAccountStatus(accId, btnEl = null) {
  await refreshSingleAccountBilling(accId, btnEl);
}

async function deleteAccount(accId) {
  confirmAction(`Delete cloud account #${accId}? All associated credentials will be removed.`, "DELETE_ACCOUNT", async () => {
    try {
      await api("delete_account", { account_id: accId, confirm: "DELETE_ACCOUNT" });
      showToast("Account removed.", "success");
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

async function unassignFloatingIp(accId, fipId, btn = null) {
  const action = async () => {
    try {
      await api("unassign_floating_ip", { account_id: accId, floating_id: fipId });
      showToast("Floating IP unassigned.", "success");
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  };
  if (btn) {
    await runWithButtonLoading(btn, action);
  } else {
    await action();
  }
}
window.unassignFloatingIp = unassignFloatingIp;

async function deleteFloatingIp(accId, fipId, ipText, btn = null) {
  confirmAction(`Permanently delete Floating IP ${ipText}?`, "DELETE_FLOATING_IP", async () => {
    try {
      await api("delete_floating_ip", { account_id: accId, floating_id: fipId, confirm: "DELETE_FLOATING_IP" });
      showToast("Floating IP deleted.", "success");
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}
window.deleteFloatingIp = deleteFloatingIp;

async function deletePrimaryIp(accId, ipId, btn = null) {
  confirmAction(`Permanently delete Hetzner Primary IP #${ipId}?`, "DELETE_PRIMARY_IP", async () => {
    try {
      await api("delete_hetzner_primary_ip", { account_id: accId, ip_id: ipId, confirm: "DELETE_PRIMARY_IP" });
      showToast("Primary IP deleted.", "success");
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}
window.deletePrimaryIp = deletePrimaryIp;

async function deleteSshKey(keyId, keyName) {
  confirmAction(`Delete SSH key '${keyName}' from vault?`, "DELETE_SSH_KEY", async () => {
    try {
      await api("delete_ssh_key", { key_id: keyId, confirm: "DELETE_SSH_KEY" });
      showToast("SSH key deleted.", "success");
      loadAll();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

async function deleteDnsRecord(zoneId, recordId) {
  confirmAction("Delete Cloudflare DNS record?", "DELETE_DNS", async () => {
    try {
      await api("delete_dns_record", { zone_id: zoneId, record_id: recordId, confirm: "DELETE_DNS" });
      showToast("DNS record deleted.", "success");
      loadDnsRecords(zoneId);
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

// ==================== UTILS ====================
function confirmAction(descOrOptions, expectedWord, onConfirm) {
  const modal = document.getElementById("modal-confirm-dialog");
  const titleEl = document.getElementById("confirm-dialog-title");
  const descEl = document.getElementById("confirm-dialog-desc");
  const typedContainer = document.getElementById("confirm-typed-container");
  const typedLabel = document.getElementById("confirm-typed-label");
  const typedInput = document.getElementById("confirm-typed-input");
  const submitBtn = document.getElementById("confirm-dialog-submit-btn");

  // Mode 1: Options object returning Promise
  if (typeof descOrOptions === "object" && descOrOptions !== null) {
    const opts = descOrOptions;
    const title = opts.title || "Confirm Action";
    const desc = opts.message || opts.desc || "Are you sure you want to proceed?";
    const word = opts.expectedWord || opts.expected || "";
    const isDanger = opts.isDanger !== false;
    const confirmText = opts.confirmText || (isDanger ? "Confirm" : "Proceed");

    if (titleEl) titleEl.textContent = title;
    if (descEl) descEl.textContent = desc;
    if (submitBtn) {
      submitBtn.textContent = confirmText;
      submitBtn.className = isDanger ? "btn btn-danger" : "btn btn-primary";
    }

    if (word) {
      if (typedContainer) typedContainer.style.display = "block";
      if (typedLabel) typedLabel.textContent = `Type "${word}" to verify:`;
      if (typedInput) typedInput.value = "";
    } else {
      if (typedContainer) typedContainer.style.display = "none";
    }

    return new Promise((resolve) => {
      let settled = false;

      const cleanup = () => {
        if (submitBtn) submitBtn.onclick = null;
        if (modal) {
          modal.removeEventListener("click", backdropHandler);
          modal.querySelectorAll("[data-close='modal-confirm-dialog']").forEach(b => {
            b.removeEventListener("click", cancelHandler);
          });
        }
      };

      const finish = (result) => {
        if (settled) return;
        settled = true;
        cleanup();
        closeModal("modal-confirm-dialog");
        resolve(result);
      };

      const handler = () => {
        if (word && typedInput && typedInput.value.trim() !== word) {
          showToast(`Verification mismatch. You must type "${word}".`, "error");
          return;
        }
        finish(true);
      };

      const cancelHandler = () => finish(false);
      const backdropHandler = (e) => {
        if (e.target === modal) finish(false);
      };

      if (submitBtn) submitBtn.onclick = handler;
      if (modal) {
        modal.addEventListener("click", backdropHandler);
        modal.querySelectorAll("[data-close='modal-confirm-dialog']").forEach(b => {
          b.addEventListener("click", cancelHandler);
        });
      }

      openModal("modal-confirm-dialog");
      if (word && typedInput) {
        setTimeout(() => typedInput.focus(), 100);
      }
    });
  }

  // Mode 2: Legacy callback signature confirmAction(desc, expectedWord, onConfirm)
  const desc = descOrOptions;
  if (titleEl) titleEl.textContent = "Confirm Action";
  if (descEl) descEl.textContent = desc;
  if (typedContainer) typedContainer.style.display = "block";
  if (typedLabel) typedLabel.textContent = `Type "${expectedWord}" to verify:`;
  if (typedInput) typedInput.value = "";
  if (submitBtn) {
    submitBtn.textContent = "Confirm";
    submitBtn.className = "btn btn-danger";
  }

  const handler = async () => {
    if (typedInput.value.trim() !== expectedWord) {
      showToast(`Verification mismatch. You must type "${expectedWord}".`, "error");
      return;
    }
    await runWithButtonLoading(submitBtn, async () => {
      try {
        await onConfirm();
        submitBtn.onclick = null;
        closeModal("modal-confirm-dialog");
      } catch (err) {
        // Error already handled in onConfirm callback
      }
    }, "Executing...");
  };

  submitBtn.onclick = handler;
  openModal("modal-confirm-dialog");
  setTimeout(() => typedInput.focus(), 100);
}

function copyText(str) {
  navigator.clipboard.writeText(str).then(() => {
    showToast("Copied to clipboard: " + str, "info");
  }).catch(() => {});
}

function downloadFile(filename, text) {
  const element = document.createElement('a');
  element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
  element.setAttribute('download', filename);
  element.style.display = 'none';
  document.body.appendChild(element);
  element.click();
  document.body.removeChild(element);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showToast(msg, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 200);
  }, 4000);
}

// ==================== UNIVERSAL BUTTON LOADING HELPERS ====================
function setButtonLoading(btn, isLoading, loadingTextOrIcon = null) {
  if (typeof btn === "string") {
    btn = document.getElementById(btn);
  }
  if (!btn || !(btn instanceof HTMLElement)) return;

  if (isLoading) {
    if (btn.dataset.isLoading === "true") return;
    btn.dataset.isLoading = "true";
    btn.dataset.originalHtml = btn.innerHTML;
    btn.dataset.originalDisabled = btn.disabled ? "true" : "false";
    btn.disabled = true;
    btn.classList.add("btn-loading");

    if (loadingTextOrIcon) {
      btn.innerHTML = `<span class="btn-spinner"></span> <span>${escapeHtml(loadingTextOrIcon)}</span>`;
    } else {
      const text = btn.textContent.trim();
      const isIconOnly = text.length <= 2 ||
        btn.classList.contains("btn-icon-sm") ||
        btn.classList.contains("btn-icon-xs") ||
        btn.classList.contains("btn-icon-only") ||
        btn.classList.contains("btn-icon-subtle");

      if (isIconOnly) {
        btn.innerHTML = `<span class="btn-spinner"></span>`;
      } else {
        btn.innerHTML = `<span class="btn-spinner"></span> <span>${escapeHtml(text || "Loading…")}</span>`;
      }
    }
  } else {
    if (btn.dataset.isLoading !== "true") return;
    btn.dataset.isLoading = "false";
    btn.classList.remove("btn-loading");
    if (btn.dataset.originalHtml !== undefined) {
      btn.innerHTML = btn.dataset.originalHtml;
      delete btn.dataset.originalHtml;
    }
    if (btn.dataset.originalDisabled === "false") {
      btn.disabled = false;
    }
    delete btn.dataset.originalDisabled;
  }
}

async function runWithButtonLoading(btn, asyncFn, loadingTextOrIcon = null) {
  setButtonLoading(btn, true, loadingTextOrIcon);
  try {
    return await asyncFn();
  } finally {
    setButtonLoading(btn, false);
  }
}
window.setButtonLoading = setButtonLoading;
window.runWithButtonLoading = runWithButtonLoading;

