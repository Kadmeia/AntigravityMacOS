// Antigravity Unlocker — Amnezia Style Frontend Engine

let currentData = null;
let isProcessing = false;
let apiToken = null;
let proxySettingsDirty = false;

// Screens
const screenMain = document.getElementById("screenMain");
const screenSettings = document.getElementById("screenSettings");
const btnOpenSettings = document.getElementById("btnOpenSettings");
const btnCloseSettings = document.getElementById("btnCloseSettings");

// Main Elements
const targetAppSelect = document.getElementById("targetAppSelect");
const targetStatusSub = document.getElementById("targetStatusSub");
const buttonHalo = document.getElementById("buttonHalo");
const btnPatchAction = document.getElementById("btnPatchAction");
const actionIcon = document.getElementById("actionIcon");
const actionTitle = document.getElementById("actionTitle");
const actionSubtitle = document.getElementById("actionSubtitle");
const permanentNoteCard = document.getElementById("permanentNoteCard");
const noteText = document.getElementById("noteText");
const footerDot = document.getElementById("footerDot");
const footerProxyText = document.getElementById("footerProxyText");
const footerPingText = document.getElementById("footerPingText");

// Settings Elements
const btnRestartApp = document.getElementById("btnRestartApp");
const btnUnpatchAll = document.getElementById("btnUnpatchAll");
const chkAutoPatch = document.getElementById("chkAutoPatch");
const routeModeSelect = document.getElementById("routeModeSelect");
const customProxyBox = document.getElementById("customProxyBox");
const proxyType = document.getElementById("proxyType");
const proxyHost = document.getElementById("proxyHost");
const proxyPort = document.getElementById("proxyPort");
const btnSaveProxy = document.getElementById("btnSaveProxy");

// Session Log Elements
const sessionLogStats = document.getElementById("sessionLogStats");
const btnToggleLog = document.getElementById("btnToggleLog");
const btnCopyLog = document.getElementById("btnCopyLog");
const logConsoleContainer = document.getElementById("logConsoleContainer");
const logConsolePath = document.getElementById("logConsolePath");
const btnRefreshLog = document.getElementById("btnRefreshLog");
const logConsoleText = document.getElementById("logConsoleText");
let isLogOpen = false;

// Toast utility
function showToast(message, type = "info") {
  const box = document.getElementById("toastBox");
  const t = document.createElement("div");
  t.className = `toast-msg ${type}`;
  t.textContent = message;
  box.appendChild(t);
  setTimeout(() => {
    t.style.opacity = "0";
    setTimeout(() => t.remove(), 250);
  }, 3500);
}

function errorMessage(error, fallback = "Операция не выполнена") {
  return error && error.message ? error.message : fallback;
}

async function initSession() {
  const params = new URLSearchParams(window.location.hash.slice(1));
  apiToken = params.get("token");
  if (!apiToken) throw new Error("Не удалось открыть защищённую сессию");
  history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
}

async function apiFetch(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  if (!apiToken) await initSession();
  if (url.startsWith("/api/")) {
    headers.set("X-Antigravity-Token", apiToken);
  }
  if (method !== "GET" && method !== "HEAD") {
    headers.set("Content-Type", "application/json");
    if (options.body === undefined) options.body = "{}";
  }
  const res = await fetch(url, { ...options, method, headers, cache: "no-store" });
  let data = {};
  try {
    data = await res.json();
  } catch (_) {
    data = {};
  }
  if (!res.ok) {
    const error = new Error(data.error || (data.action && data.action.message) || `HTTP ${res.status}`);
    error.data = data;
    error.status = res.status;
    throw error;
  }
  return data;
}

// Navigation between Main and Settings
btnOpenSettings.addEventListener("click", () => {
  screenMain.classList.remove("active");
  screenSettings.classList.add("active");
  fetchSessionLogs();
});

btnCloseSettings.addEventListener("click", () => {
  screenSettings.classList.remove("active");
  screenMain.classList.add("active");
});

// Fetch Status
async function loadStatus() {
  try {
    const data = await apiFetch("/api/status");
    currentData = data;
    render(data);
  } catch (err) {
    console.error("loadStatus error:", err);
  }
}

// Check patch status for currently selected target
function isTargetPatched(data, target) {
  const apps = data.apps || [];
  const installedApps = apps.filter(a => a.installed);
  const targetInstalled = target === "all"
    ? installedApps.length > 0
    : installedApps.some(app => app.id === target);
  btnPatchAction.disabled = isProcessing || !targetInstalled;
  btnPatchAction.setAttribute("aria-busy", isProcessing ? "true" : "false");
  if (target === "all") {
    const installed = apps.filter(a => a.installed);
    return installed.length > 0 && installed.every(a => a.is_patched);
  }
  const app = apps.find(a => a.id === target);
  return app && app.installed && app.is_patched;
}

// Dynamically sync options in targetAppSelect with detected applications
function syncTargetSelectOptions(apps, selectedTarget) {
  const existingValues = new Set(Array.from(targetAppSelect.options).map(o => o.value));

  apps.forEach(app => {
    if (!existingValues.has(app.id) && app.installed) {
      const opt = document.createElement("option");
      opt.value = app.id;
      let icon = "⚙️";
      if (app.icon_type === "ide") icon = "💻";
      else if (app.icon_type === "desktop") icon = "🚀";
      else if (app.icon_type === "cli") icon = "⌨️";
      opt.textContent = `${icon} ${app.name}`;
      targetAppSelect.appendChild(opt);
    }
  });

  if (selectedTarget && document.activeElement !== targetAppSelect) {
    const optionExists = Array.from(targetAppSelect.options).some(o => o.value === selectedTarget);
    if (optionExists) targetAppSelect.value = selectedTarget;
  }
}

// Render UI based on backend data
function render(data) {
  const apps = data.apps || [];
  syncTargetSelectOptions(apps, data.selected_target);

  const currentTarget = targetAppSelect.value;
  const targetPatched = isTargetPatched(data, currentTarget);

  // Update target status sublabel
  if (currentTarget === "all") {
    const patchedCount = apps.filter(a => a.installed && a.is_patched).length;
    const totalCount = apps.filter(a => a.installed).length;
    if (targetPatched) {
      targetStatusSub.textContent = `Все программы защищены (${patchedCount}/${totalCount})`;
      targetStatusSub.className = "target-status-sub patched";
    } else {
      targetStatusSub.textContent = totalCount === 0
        ? "Приложения Antigravity не найдены"
        : `⚠️ Требуется снять защиту (${patchedCount}/${totalCount} пропатчено)`;
      targetStatusSub.className = "target-status-sub unpatched";
    }
  } else {
    const app = apps.find(a => a.id === currentTarget);
    if (!app || !app.installed) {
      targetStatusSub.textContent = "Не найдено в системе";
      targetStatusSub.className = "target-status-sub unpatched";
    } else if (app.is_patched) {
      targetStatusSub.textContent = `Защита снята (v${app.version || "Latest"})`;
      targetStatusSub.className = "target-status-sub patched";
    } else {
      targetStatusSub.textContent = `⚠️ Требуется патч (v${app.version || "Latest"})`;
      targetStatusSub.className = "target-status-sub unpatched";
    }
  }

  // Update Main Action Button
  if (targetPatched) {
    btnPatchAction.classList.add("active");
    buttonHalo.classList.add("active");
    actionIcon.innerHTML = `
      <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        <polyline points="9 12 11 14 15 10"></polyline>
      </svg>
    `;
    actionTitle.textContent = "Пропатчить снова";
    actionSubtitle.textContent = "Проверить и применить текущий патч";
    
    permanentNoteCard.classList.remove("unpatched");
    noteText.innerHTML = `Патч уже установлен. Кнопка <strong>«Пропатчить снова»</strong> повторно проверит файлы и применит недостающие изменения.`;
  } else {
    btnPatchAction.classList.remove("active");
    buttonHalo.classList.remove("active");
    actionIcon.innerHTML = `
      <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
      </svg>
    `;
    actionTitle.textContent = "Снять защиту";
    actionSubtitle.textContent = "Нажмите для разблокировки";

    permanentNoteCard.classList.add("unpatched");
    noteText.innerHTML = `Нажмите кнопку <strong>«Снять защиту»</strong> для автоматического обхода ограничений региона и аккаунта Google.`;
  }

  // Footer status
  const proxyRunning = data.proxy && data.proxy.running;
  if (proxyRunning) {
    footerDot.className = "status-dot green";
    footerProxyText.textContent = `Служба ${data.proxy.port || 53129}: Активна`;
  } else {
    footerDot.className = "status-dot amber";
    footerProxyText.textContent = `Служба ${data.proxy ? data.proxy.port : 53129}: Остановлена`;
  }
  if (footerPingText) {
    footerPingText.textContent = targetPatched ? "Защита активна" : "Готов к работе";
  }

  // Settings sync
  if (data.config) {
    chkAutoPatch.checked = data.config.auto_patch_on_launch !== false;
    routeModeSelect.value = data.config.route_mode || "smart";
    if (data.config.route_mode === "custom") {
      customProxyBox.style.display = "block";
    } else {
      customProxyBox.style.display = "none";
    }

    if (data.config.custom_proxy && !proxySettingsDirty) {
      proxyType.value = data.config.custom_proxy.type || "http";
      proxyHost.value = data.config.custom_proxy.host || "127.0.0.1";
      proxyPort.value = data.config.custom_proxy.port || "7890";
    }
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Selector change
targetAppSelect.addEventListener("change", () => {
  if (currentData) {
    render(currentData);
  }
  apiFetch("/api/settings", {
    method: "POST",
    body: JSON.stringify({ selected_target: targetAppSelect.value })
  }).catch(err => showToast(errorMessage(err, "Не удалось сохранить выбор"), "error"));
});

// Central Action Button Click
btnPatchAction.addEventListener("click", async () => {
  if (isProcessing) return;

  const currentTarget = targetAppSelect.value;
  const targetPatched = currentData ? isTargetPatched(currentData, currentTarget) : false;

  isProcessing = true;
  btnPatchAction.disabled = true;
  actionTitle.textContent = targetPatched ? "Проверяем патч..." : "Патчим...";
  actionSubtitle.textContent = targetPatched ? "Повторное применение изменений" : "Применение изменений и подпись";
  btnPatchAction.style.opacity = "0.7";

  try {
    const data = await apiFetch("/api/patch_now", {
      method: "POST",
      body: JSON.stringify({ target: currentTarget, launch_after_patch: true })
    });
    currentData = data;
    render(data);
    showToast((data.action && data.action.message) || "Изменения применены", "success");
  } catch (err) {
    console.error("Patch error:", err);
    if (err.data && err.data.apps) {
      currentData = err.data;
      render(err.data);
    }
    showToast(errorMessage(err, "Ошибка при снятии защиты"), "error");
  } finally {
    isProcessing = false;
    btnPatchAction.style.opacity = "1";
    if (currentData) render(currentData);
  }
});

// Unpatch All (Settings)
btnUnpatchAll.addEventListener("click", async () => {
  const target = targetAppSelect.value;
  const targetName = targetAppSelect.selectedOptions[0]?.textContent || "выбранную программу";
  if (!confirm(`Снять патч с ${targetName}? Автопатч для этой программы выключится. Исходная подпись Google восстанавливается только при официальной переустановке.`)) return;
  try {
    showToast("Выполняется откат...", "info");
    const data = await apiFetch("/api/unpatch_now", {
      method: "POST",
      body: JSON.stringify({ target })
    });
    currentData = data;
    render(data);
    showToast((data.action && data.action.message) || "Патч снят", "info");
  } catch (e) {
    if (e.data && e.data.apps) render(e.data);
    showToast(errorMessage(e, "Ошибка при откате"), "error");
  }
});

// Restart Antigravity (Settings)
btnRestartApp.addEventListener("click", async () => {
  if (btnRestartApp.disabled) return;
  btnRestartApp.disabled = true;
  try {
    showToast("Перезапуск Antigravity...", "info");
    const selected = targetAppSelect.value;
    const installed = (currentData && currentData.apps || []).filter(app => app.installed);
    let targetApp = null;
    if (selected === "all") {
      targetApp = installed.find(app => app.id === "antigravity_desktop")
        || installed.find(app => app.id === "antigravity_ide");
    } else {
      targetApp = installed.find(app => app.id === selected);
    }
    const appId = targetApp ? targetApp.id : null;
    if (!appId || appId === "antigravity_cli") throw new Error("Выберите Antigravity IDE или Desktop для перезапуска");
    const data = await apiFetch("/api/restart_app", {
      method: "POST",
      body: JSON.stringify({ app_id: appId })
    });
    showToast(data.message, data.success ? "success" : "error");
    loadStatus();
  } catch (e) {
    showToast(errorMessage(e, "Ошибка перезапуска"), "error");
  } finally {
    btnRestartApp.disabled = false;
  }
});

// Auto-patch Checkbox (Settings)
chkAutoPatch.addEventListener("change", async (e) => {
  try {
    await apiFetch("/api/settings", {
      method: "POST",
      body: JSON.stringify({ auto_patch_on_launch: e.target.checked })
    });
    showToast(`Автопатч при обновлениях: ${e.target.checked ? 'Вкл' : 'Выкл'}`, "info");
  } catch (err) {
    e.target.checked = !e.target.checked;
    showToast(errorMessage(err, "Не удалось сохранить настройку"), "error");
  }
});

// Route Mode Selector (Settings)
routeModeSelect.addEventListener("change", async (e) => {
  const mode = e.target.value;
  if (mode === "custom") {
    customProxyBox.style.display = "block";
  } else {
    customProxyBox.style.display = "none";
  }

  try {
    await apiFetch("/api/settings", {
      method: "POST",
      body: JSON.stringify({ route_mode: mode })
    });
    const modeLabels = {
      smart: "Автовыбор (Smart)",
      tls_split: "Обход DPI (Фрагментация TLS)",
      custom: "Свой прокси (Custom)",
      direct: "Прямое соединение (Direct)"
    };
    showToast(`Режим маршрутизации: ${modeLabels[mode] || mode}`, "info");
  } catch (err) {
    showToast(errorMessage(err, "Не удалось сохранить режим"), "error");
    loadStatus();
  }
});

// Preserve edits when a background status refresh arrives.
[proxyType, proxyHost, proxyPort].forEach(input => {
  input.addEventListener("input", () => { proxySettingsDirty = true; });
  input.addEventListener("change", () => { proxySettingsDirty = true; });
});

// Save Proxy Settings
btnSaveProxy.addEventListener("click", async () => {
  try {
    await apiFetch("/api/settings", {
      method: "POST",
      body: JSON.stringify({
        route_mode: "custom",
        custom_proxy: {
          type: proxyType.value,
          host: proxyHost.value.trim(),
          port: parseInt(proxyPort.value) || 7890
        }
      })
    });
    proxySettingsDirty = false;
    showToast("Параметры своего прокси сохранены!", "success");
  } catch (e) {
    showToast("Ошибка сохранения", "error");
  }
});

// Smart Adaptive Polling (saves battery / CPU when window is backgrounded)
let pollIntervalId = null;
function setPollFrequency(ms) {
  if (pollIntervalId) clearInterval(pollIntervalId);
  pollIntervalId = setInterval(loadStatus, ms);
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    setPollFrequency(10000); // 10s when backgrounded
  } else {
    loadStatus();
    setPollFrequency(3500); // 3.5s when active
  }
});

// Session Log Handlers
async function fetchSessionLogs() {
  try {
    const data = await apiFetch("/api/session/logs");
    if (data.summary) {
      const s = data.summary;
      if (sessionLogStats) {
        sessionLogStats.textContent = `Подключений: ${s.total_connections} | Успешно: ${s.success_connections} | Сбоев: ${s.failed_connections}`;
        if (s.failed_connections > 0) {
          sessionLogStats.style.color = "var(--accent-amber)";
        } else {
          sessionLogStats.style.color = "var(--text-muted)";
        }
      }
      if (s.log_file_path && logConsolePath) {
        logConsolePath.textContent = s.log_file_path;
      }
    }
    if (logConsoleText && (data.raw_tail !== undefined || data.recent)) {
      logConsoleText.textContent = data.raw_tail || JSON.stringify(data.recent, null, 2);
      logConsoleText.scrollTop = logConsoleText.scrollHeight;
    }
    return data;
  } catch (err) {
    console.error("fetchSessionLogs error:", err);
  }
}

if (btnToggleLog) {
  btnToggleLog.addEventListener("click", () => {
    isLogOpen = !isLogOpen;
    if (isLogOpen) {
      logConsoleContainer.style.display = "flex";
      btnToggleLog.textContent = "Скрыть";
      fetchSessionLogs();
    } else {
      logConsoleContainer.style.display = "none";
      btnToggleLog.textContent = "Показать";
    }
  });
}

if (btnRefreshLog) {
  btnRefreshLog.addEventListener("click", async () => {
    btnRefreshLog.disabled = true;
    await fetchSessionLogs();
    btnRefreshLog.disabled = false;
    showToast("Журнал обновлен", "info");
  });
}

if (btnCopyLog) {
  btnCopyLog.addEventListener("click", async () => {
    try {
      const data = await fetchSessionLogs();
      const textToCopy = (data && data.raw_tail) || logConsoleText.textContent;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(textToCopy);
      } else {
        const ta = document.createElement("textarea");
        ta.value = textToCopy;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      showToast("Журнал скопирован в буфер обмена!", "success");
    } catch (e) {
      showToast("Не удалось скопировать журнал", "error");
    }
  });
}

// Open external URLs in default system browser
function openExternalUrl(event, url) {
  if (event) {
    if (typeof event.preventDefault === "function") {
      event.preventDefault();
    }
    if (typeof event.stopPropagation === "function") {
      event.stopPropagation();
    }
  }
  if (!url) return;
  fetch("/api/open-url", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Antigravity-Token": apiToken || "",
    },
    body: JSON.stringify({ url: url }),
  }).catch(() => {
    window.open(url, "_blank", "noopener,noreferrer");
  });
}
window.openExternalUrl = openExternalUrl;

// Initial startup
initSession().then(loadStatus).catch(err => showToast(errorMessage(err), "error"));
setPollFrequency(3500);
