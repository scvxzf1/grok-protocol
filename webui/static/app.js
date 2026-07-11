const $ = (id) => document.getElementById(id);
const form = $("cfgForm");
const message = $("message");
const logBox = $("logBox");
let es = null;

// ---- UI performance: buffer logs / throttle snapshot ----
const LOG_MAX_LINES = 200;
const SNAPSHOT_MIN_INTERVAL_MS = 1000;
const LOG_FLUSH_MS = 500;
const WORKER_RENDER_LIMIT = 12;

let logLines = [];
let logPending = [];
let logFlushTimer = null;
let lastSnapshotAt = 0;
let pendingSnapshot = null;
let snapshotTimer = null;
let esReconnectTimer = null;
let esShouldRun = false;

function setMsg(text, isError=false) {
  message.textContent = text || "";
  message.style.color = isError ? "#ff6b6b" : "#f0b429";
}

function syncTargetModeFields() {
  const mode = form.target_mode ? form.target_mode.value : "count";
  const countField = $("countField");
  const targetField = $("targetSuccessField");
  if (countField) countField.style.display = mode === "continuous" ? "none" : "";
  if (targetField) targetField.style.display = mode === "continuous" ? "" : "none";
}

function formData() {
  const fd = new FormData(form);
  return {
    run_mode: fd.get("run_mode"),
    turnstile_provider: fd.get("turnstile_provider"),
    turnstile_headless: form.turnstile_headless.checked,
    target_mode: fd.get("target_mode") || "count",
    target_success: Number(fd.get("target_success") || 0),
    count: Number(fd.get("count") || 1),
    workers: Number(fd.get("workers") || 1),
    proxy_mode: fd.get("proxy_mode"),
    output_dir: fd.get("output_dir"),
    sso_convert_retries: Number(fd.get("sso_convert_retries") || 5),
    sso_convert_cooldown: Number(fd.get("sso_convert_cooldown") || 3),
  };
}

function fillForm(data) {
  form.run_mode.value = data.run_mode || "register_otp";
  form.turnstile_provider.value = data.turnstile_provider || "local";
  form.turnstile_headless.checked = !!data.turnstile_headless;
  if (form.target_mode) form.target_mode.value = data.target_mode || data.run_target_mode || "count";
  if (form.target_success) form.target_success.value = data.target_success != null ? data.target_success : 0;
  form.count.value = data.count || 1;
  form.workers.value = data.workers || 1;
  form.proxy_mode.value = data.proxy_mode || "auto";
  form.output_dir.value = data.output_dir || "";
  form.sso_convert_retries.value = data.sso_convert_retries || 5;
  form.sso_convert_cooldown.value = data.sso_convert_cooldown || 3;
  $("emailProvider").textContent = "邮箱: " + (data.email_provider || (data.config && data.config.email_provider) || "-");
  syncTargetModeFields();
}

async function api(path, opts={}) {
  const r = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const text = await r.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = { detail: text }; }
  if (!r.ok) {
    const detail = (body && body.detail) ? body.detail : r.statusText;
    throw new Error(detail);
  }
  return body;
}

async function loadSettings() {
  const data = await api("/api/settings");
  fillForm(data);
}

if (form.target_mode) form.target_mode.onchange = syncTargetModeFields;

function flushLogs() {
  logFlushTimer = null;
  if (!logPending.length || !logBox) return;
  const stick =
    $("autoScroll") &&
    $("autoScroll").checked &&
    (logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 40);
  for (const line of logPending) logLines.push(line);
  logPending = [];
  if (logLines.length > LOG_MAX_LINES) {
    logLines = logLines.slice(-LOG_MAX_LINES);
  }
  // One DOM write per batch.
  logBox.textContent = logLines.join("\n") + (logLines.length ? "\n" : "");
  if (stick) logBox.scrollTop = logBox.scrollHeight;
}

function liveLogsEnabled() {
  const el = $("liveLogs");
  return !!(el && el.checked);
}

function appendLog(line) {
  if (!line) return;
  // Hard gate: when live logs are off, never touch the log DOM.
  if (!liveLogsEnabled()) return;
  logPending.push(String(line));
  if (logPending.length > 300) {
    logPending = logPending.slice(-150);
  }
  if (!logFlushTimer) {
    logFlushTimer = setTimeout(flushLogs, LOG_FLUSH_MS);
  }
}

function clearLogs() {
  logLines = [];
  logPending = [];
  if (logFlushTimer) {
    clearTimeout(logFlushTimer);
    logFlushTimer = null;
  }
  if (logBox) logBox.textContent = "";
}

function formatElapsed(sec) {
  const n = Math.max(0, Number(sec) || 0);
  if (n < 60) return `${n}s`;
  const m = Math.floor(n / 60);
  const s = n % 60;
  return `${m}m${String(s).padStart(2, "0")}s`;
}

function formatSpeed(v) {
  if (v === null || v === undefined || Number.isNaN(Number(v))) return "-";
  return `${Number(v).toFixed(1)} 个/分钟`;
}

function formatRate(v) {
  if (v === null || v === undefined || Number.isNaN(Number(v))) return "-";
  return `${(Number(v) * 100).toFixed(1)}%`;
}

function renderSnapshotNow(snap) {
  if (!snap) return;
  lastSnapshotAt = Date.now();
  const mode = String(snap.target_mode || "count");
  const total = snap.count || 0;
  const done = (snap.completed || 0);
  const startedTasks = Number(snap.started_tasks != null ? snap.started_tasks : done);
  let pct = 0;
  if (mode === "continuous") {
    const target = Number(snap.target_success || 0);
    pct = target > 0 ? Math.min(100, Math.round((snap.succeeded || 0) * 100 / target)) : Math.min(100, Number(snap.active || 0) > 0 ? 15 : (done ? 100 : 0));
  } else {
    pct = total ? Math.round(done * 100 / total) : 0;
  }
  $("progressBar").style.width = pct + "%";
  const stopped = Number(snap.stopped || 0);
  const stopPart = stopped > 0 ? ` | 停止 ${stopped}` : "";
  let line1 = "";
  if (mode === "continuous") {
    const target = Number(snap.target_success || 0);
    const targetText = target > 0 ? String(target) : "不限";
    line1 = `run=${snap.run_id || "-"} | 持续运行 | 已启动 ${startedTasks} | 成功 ${snap.succeeded || 0}/${targetText} | 失败 ${snap.failed || 0}${stopPart} | 活动 ${snap.active || 0}`;
  } else {
    line1 = `run=${snap.run_id || "-"} | 完成 ${done}/${total} | 成功 ${snap.succeeded || 0} | 失败 ${snap.failed || 0}${stopPart} | 活动 ${snap.active || 0}`;
  }
  const phase = snap.phase ? ` | 阶段 ${snap.phase}` : "";
  const pauseReason = snap.refill_pause_reason || snap.pause_reason || "";
  const paused = !!snap.refill_paused;
  const circuit = !!snap.circuit_open;
  const proxyBad = !!snap.proxy_unhealthy;
  let pausePart = "";
  if (paused || circuit || proxyBad) {
    const tags = [];
    if (circuit) tags.push("熔断");
    if (proxyBad) tags.push("代理不可用");
    if (paused && !circuit && !proxyBad) tags.push("补货暂停");
    const why = pauseReason ? `：${String(pauseReason).slice(0, 80)}` : "";
    pausePart = ` | ${tags.join('+')}${why}`;
  }
  const recentTotal = Number(snap.recent_total || 0);
  const recentRate = snap.recent_fail_rate;
  const recentPart = recentTotal > 0
    ? ` | 近窗失败 ${snap.recent_fail_count || 0}/${recentTotal} (${formatRate(recentRate)})`
    : "";
  const line2 = `速度 ${formatSpeed(snap.avg_success_per_min)} | 成功率 ${formatRate(snap.success_rate)} | 耗时 ${formatElapsed(snap.elapsed_sec)}${phase}${recentPart}${pausePart}`;
  $("progressStats").textContent = `${line1}\n${line2}`;
  const fc = snap.failure_counts || {};
  $("failureBox").textContent = Object.keys(fc).length
    ? Object.entries(fc).map(([k,v]) => `${k}: ${v}`).join("\n")
    : "-";

  const workers = Array.isArray(snap.workers) ? snap.workers : [];
  // Prefer active/failed first, keep DOM small.
  const ranked = workers.slice().sort((a, b) => {
    const rank = (w) => {
      const s = String(w.status || "");
      if (s === "running" || s === "active" || s === "converting") return 0;
      if (s === "failed") return 1;
      if (s === "queued") return 2;
      if (s === "succeeded") return 3;
      return 4;
    };
    return rank(a) - rank(b) || (a.index || 0) - (b.index || 0);
  });
  const shown = ranked.slice(0, WORKER_RENDER_LIMIT);
  const backendExtra = Number(snap.workers_truncated || 0);
  const extra = backendExtra > 0
    ? backendExtra + Math.max(0, workers.length - shown.length)
    : Math.max(0, (Number(snap.worker_total || workers.length) - shown.length));
  const body = shown.map((w) => {
    const log = String(w.last_log || "").replace(/\s+/g, " ").slice(0, 100);
    return `W${String(w.index).padStart(2,"0")} ${w.status || "-"} | ${log}`;
  });
  if (extra > 0) body.push(`... 另有 ${extra} 个 worker 未展开`);
  $("workerTable").textContent = body.length ? body.join("\n") : "-";

  const badge = $("busyBadge");
  if (snap.done) {
    badge.textContent = "已完成";
    badge.className = "badge";
    setFormDisabled(false);
    esShouldRun = false;
  } else if (snap.started) {
    if (snap.stopping) {
      badge.textContent = "停止中";
      badge.className = "badge run";
    } else if (snap.circuit_open) {
      badge.textContent = "熔断暂停";
      badge.className = "badge warn";
    } else if (snap.proxy_unhealthy || snap.refill_paused) {
      badge.textContent = "补货暂停";
      badge.className = "badge warn";
    } else {
      badge.textContent = "运行中";
      badge.className = "badge run";
    }
    setFormDisabled(true);
  }
}

function renderSnapshot(snap) {
  if (!snap) return;
  const now = Date.now();
  // Always apply terminal states immediately.
  if (snap.done || !lastSnapshotAt || now - lastSnapshotAt >= SNAPSHOT_MIN_INTERVAL_MS) {
    pendingSnapshot = null;
    if (snapshotTimer) {
      clearTimeout(snapshotTimer);
      snapshotTimer = null;
    }
    renderSnapshotNow(snap);
    return;
  }
  pendingSnapshot = snap;
  if (!snapshotTimer) {
    snapshotTimer = setTimeout(() => {
      snapshotTimer = null;
      if (pendingSnapshot) {
        const s = pendingSnapshot;
        pendingSnapshot = null;
        renderSnapshotNow(s);
      }
    }, SNAPSHOT_MIN_INTERVAL_MS - (now - lastSnapshotAt));
  }
}

function setFormDisabled(disabled) {
  [...form.elements].forEach(el => el.disabled = disabled);
}

function disconnectEvents() {
  esShouldRun = false;
  if (esReconnectTimer) {
    clearTimeout(esReconnectTimer);
    esReconnectTimer = null;
  }
  if (es) {
    try { es.close(); } catch {}
    es = null;
  }
}

function eventsUrl() {
  const params = new URLSearchParams();
  params.set("logs", liveLogsEnabled() ? "1" : "0");
  params.set("worker_limit", String(WORKER_RENDER_LIMIT));
  return "/api/runs/current/events?" + params.toString();
}

function connectEvents() {
  disconnectEvents();
  esShouldRun = true;
  // logs=0 by default: backend skips log fanout entirely during batches.
  es = new EventSource(eventsUrl());
  es.addEventListener("snapshot", (e) => {
    try { renderSnapshot(JSON.parse(e.data)); }
    catch {}
  });
  es.addEventListener("log", (e) => {
    if (!liveLogsEnabled()) return;
    try {
      const data = JSON.parse(e.data);
      appendLog(data.line || "");
    } catch {
      appendLog(e.data || "");
    }
  });
  es.addEventListener("done", (e) => {
    try { renderSnapshot(JSON.parse(e.data)); }
    catch {}
    disconnectEvents();
    refreshHistory().catch(() => {});
  });
  es.onerror = () => {
    // Browser auto-reconnects EventSource; avoid stacking custom loops unless closed.
    if (!esShouldRun) return;
    if (es && es.readyState === EventSource.CLOSED) {
      if (esReconnectTimer) return;
      esReconnectTimer = setTimeout(() => {
        esReconnectTimer = null;
        if (esShouldRun) connectEvents();
      }, 1500);
    }
  };
}

async function refreshHistory() {
  const data = await api("/api/runs?limit=20");
  const box = $("historyList");
  box.innerHTML = "";
  const frag = document.createDocumentFragment();
  (data.runs || []).forEach(run => {
    const div = document.createElement("div");
    div.className = "hist-item";
    div.innerHTML = `<span>${run.run_id}</span><span>成功${run.succeeded || 0}/失败${run.failed || 0}</span>`;
    div.onclick = async () => {
      try {
        const detail = await api(`/api/runs/${encodeURIComponent(run.run_id)}`);
        // Keep history detail light: drop huge nested blobs if present.
        const slim = {
          run_id: detail.run_id || run.run_id,
          summary: detail.summary || detail,
          files: (detail.files || []).slice(0, 30),
        };
        $("historyDetail").textContent = JSON.stringify(slim, null, 2);
      } catch (e) {
        $("historyDetail").textContent = String(e.message || e);
      }
    };
    frag.appendChild(div);
  });
  box.appendChild(frag);
}

$("btnReload").onclick = async () => {
  try {
    await api("/api/settings/reload", { method: "POST", body: "{}" });
    await loadSettings();
    setMsg("配置已重载");
  } catch (e) { setMsg(String(e.message || e), true); }
};

$("btnSave").onclick = async () => {
  try {
    await api("/api/settings", { method: "PUT", body: JSON.stringify(formData()) });
    await loadSettings();
    setMsg("配置已保存");
  } catch (e) { setMsg(String(e.message || e), true); }
};

$("btnStart").onclick = async () => {
  try {
    const snap = await api("/api/runs", { method: "POST", body: JSON.stringify(formData()) });
    setMsg("批次已启动: " + (snap.run_id || ""));
    if (liveLogsEnabled()) appendLog("[UI] 批次启动 " + (snap.run_id || ""));
    else if (logBox) logBox.textContent = "批次运行中：实时日志关闭（可手动打开）\nrun=" + (snap.run_id || "");
    renderSnapshot(snap);
    connectEvents();
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
};

$("btnStop").onclick = async () => {
  try {
    const snap = await api("/api/runs/current/stop", { method: "POST", body: "{}" });
    renderSnapshot(snap);
    setMsg("已请求停止");
  } catch (e) { setMsg(String(e.message || e), true); }
};

$("btnBrowser").onclick = async () => {
  try {
    const data = await api("/api/browser/health");
    setMsg(data.summary || "ok");
  } catch (e) { setMsg(String(e.message || e), true); }
};

$("btnCleanup").onclick = async () => {
  if (!confirm("清理 Playwright 残留和 /tmp 临时浏览器目录？")) return;
  try {
    const data = await api("/api/browser/cleanup", { method: "POST", body: "{}" });
    setMsg(data.summary || "cleaned");
  } catch (e) { setMsg(String(e.message || e), true); }
};

$("btnClearLog").onclick = () => { clearLogs(); if (!liveLogsEnabled() && logBox) logBox.textContent = "实时日志已关闭（只显示进度）"; };
if ($("liveLogs")) {
  $("liveLogs").onchange = () => {
    if (liveLogsEnabled()) {
      if (logBox && /实时日志已关闭/.test(logBox.textContent || "")) logBox.textContent = "";
      appendLog("[UI] 已开启实时日志");
    } else {
      clearLogs();
      if (logBox) logBox.textContent = "实时日志已关闭（只显示进度）";
      setMsg("已关闭实时日志，进度继续刷新");
    }
    // Reconnect SSE so backend can attach/detach log listeners immediately.
    if (esShouldRun) connectEvents();
  };
}
$("btnRefreshHistory").onclick = () => refreshHistory().catch(e => setMsg(String(e.message || e), true));


function renderEmbeddedProxyStatus(data) {
  const summary = $("embeddedProxySummaryRun");
  const box = $("embeddedProxyStatusRun");
  const badge = $("embeddedBadge");
  if (!data) data = {};
  const enabled = !!data.enabled;
  const running = !!data.running;
  const phase = String(data.phase || (running ? "ready" : enabled ? "idle" : "disabled"));
  const healthy = data.healthy == null ? "-" : data.healthy;
  const total = data.total == null ? "-" : data.total;
  const leases = data.leases == null ? "-" : data.leases;
  const message = data.message || data.last_error || "";
  const phaseText = {
    starting: "启动中",
    ready: "就绪",
    error: "失败",
    disabled: "未启用",
    idle: "空闲",
  }[phase] || phase;
  if (summary) {
    summary.textContent =
      `状态: ${enabled ? "已启用" : "未启用"} | ${phaseText}` +
      ` | ${running ? "运行中" : "未运行"} | 健康 ${healthy}/${total} | 租约 ${leases}` +
      (message ? ` | ${message}` : "");
  }
  // Run console only needs a compact view; full node dump freezes the page.
  if (box) {
    const nodes = Array.isArray(data.nodes) ? data.nodes : [];
    const top = nodes.slice(0, 8).map((n, i) => {
      const name = String(n.name || n.id || "-").slice(0, 40);
      const h = n.healthy ? "Y" : "n";
      const sc = n.success_count == null ? "-" : n.success_count;
      const fc = n.fail_count == null ? "-" : n.fail_count;
      return `${i + 1}. [${h}] ${name} ok=${sc} fail=${fc}`;
    });
    const lines = [
      `phase=${phase} running=${running} healthy=${healthy}/${total} leases=${leases}`,
      message ? `message=${message}` : "",
      top.length ? "nodes:" : "nodes: -",
      ...top,
      nodes.length > 8 ? `... 另有 ${nodes.length - 8} 个节点` : "",
    ].filter(Boolean);
    box.textContent = lines.join("\n");
  }
  if (badge) {
    let label = `内嵌代理: ${phaseText}`;
    if (enabled && (healthy !== "-" || total !== "-")) label += ` ${healthy}/${total}`;
    badge.textContent = label;
    badge.className = "badge";
    if (phase === "ready" && running) badge.classList.add("good");
    else if (phase === "starting") badge.classList.add("warn");
    else if (phase === "error") badge.classList.add("err");
  }
}

async function refreshEmbeddedProxyStatus() {
  try {
    // compact=1 avoids huge node payloads on the run console.
    const data = await api("/api/embedded-proxy/status?compact=1");
    renderEmbeddedProxyStatus(data || {});
    return data;
  } catch (e) {
    renderEmbeddedProxyStatus({
      enabled: false,
      phase: "error",
      message: String(e.message || e),
      running: false,
      healthy: 0,
      total: 0,
      leases: 0,
    });
    throw e;
  }
}

let embeddedPollTimer = null;
function batchIsRunning() {
  const badge = $("busyBadge");
  const t = badge ? String(badge.textContent || "") : "";
  return t === "运行中" || t === "停止中";
}
function startEmbeddedProxyPolling() {
  if (embeddedPollTimer) return;
  const tick = async () => {
    try {
      // During a live batch, freeze proxy DOM thrash; only keep a slow heartbeat.
      if (batchIsRunning()) {
        embeddedPollTimer = setTimeout(tick, 30000);
        return;
      }
      const data = await refreshEmbeddedProxyStatus();
      const phase = String((data && data.phase) || "");
      const delay = phase === "starting" ? 2500 : 15000;
      embeddedPollTimer = setTimeout(tick, delay);
    } catch {
      embeddedPollTimer = setTimeout(tick, batchIsRunning() ? 30000 : 15000);
    }
  };
  tick();
}


(async function init() {
  try {
    await loadSettings();
    const cur = await api("/api/runs/current");
    if (cur.run) {
      renderSnapshot(cur.run);
      if (!cur.run.done) connectEvents();
    }
    await refreshHistory();
    const health = await api("/api/health");
    if (health.busy) $("busyBadge").textContent = "运行中";
    if (health.embedded_proxy) renderEmbeddedProxyStatus(health.embedded_proxy);
    startEmbeddedProxyPolling();
  } catch (e) {
    setMsg(String(e.message || e), true);
    startEmbeddedProxyPolling();
  }
})();
