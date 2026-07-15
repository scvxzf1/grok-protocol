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

function encodeEgressMode(proxyMode, embeddedEnabled) {
  const mode = String(proxyMode || "auto").toLowerCase();
  const emb = !!embeddedEnabled;
  if (emb && mode === "none") return "nodes";
  if (emb && (mode === "pool" || mode === "auto")) return "hybrid";
  if (!emb && mode === "pool") return "http";
  if (!emb && mode === "direct") return "direct";
  if (emb && mode === "direct") return "direct";
  if (!emb && mode === "auto") return "auto";
  if (!emb && mode === "none") return "off";
  if (emb) return "nodes";
  return "auto";
}

function egressModeLabel(mode) {
  const labels = {
    nodes: "只用节点池",
    http: "只用 HTTP 池",
    hybrid: "一起用",
    direct: "固定一个",
    auto: "自动",
    off: "完全关闭",
  };
  return labels[mode] || mode || "-";
}

function egressModeHintText(mode) {
  const tips = {
    nodes: "VLESS/Hy2 订阅 → mihomo；不走 HTTP 池。",
    http: "只走 fixtures/proxies.txt / 订阅 HTTP。",
    hybrid: "节点池 + HTTP 池轮询，一边挂了换另一边。",
    direct: "所有任务用配置里的固定 HTTP 代理 URL。",
    auto: "有固定 URL 用固定，否则走 HTTP 池；默认不启节点池。",
    off: "节点池和 HTTP 池都关，本机直连。",
  };
  return tips[mode] || "";
}

function currentEgressMode() {
  const el = form && form.egress_mode ? form.egress_mode : $("egressModeSelect");
  return el ? String(el.value || "auto") : "auto";
}

function syncEgressModeHint() {
  const mode = currentEgressMode();
  const hint = $("egressModeRunHint");
  if (hint) hint.textContent = `当前出口：${egressModeLabel(mode)}。${egressModeHintText(mode)}`;
  const title = $("egressStatusTitle");
  if (title) {
    const titles = {
      nodes: "节点池状态",
      http: "HTTP 池状态",
      hybrid: "混合出口状态",
      direct: "固定代理状态",
      auto: "自动出口状态",
      off: "出口状态",
    };
    title.textContent = titles[mode] || "出口状态";
  }
  if (typeof scheduleEgressStatusRefresh === "function") {
    scheduleEgressStatusRefresh(120);
  }
}

function syncTargetModeFields() {
  const mode = form.target_mode ? form.target_mode.value : "count";
  const countField = $("countField");
  const targetField = $("targetSuccessField");
  const msRow = $("msTargetRow");
  // ms_mail_all behaves like fixed count, but count is driven by mailbox pool size.
  if (countField) countField.style.display = mode === "continuous" ? "none" : "";
  if (targetField) targetField.style.display = mode === "continuous" ? "" : "none";
  if (msRow) msRow.style.display = mode === "continuous" ? "none" : "";
  const countInput = form.count;
  if (countInput) {
    if (mode === "ms_mail_all") {
      countInput.readOnly = true;
      countInput.title = "全部微软邮箱模式下由邮箱池有效条数自动填写";
    } else {
      countInput.readOnly = false;
      countInput.title = "";
    }
  }
}

function formData() {
  const fd = new FormData(form);
  const uiMode = String(fd.get("target_mode") || "count");
  // Backend only understands count/continuous; ms_mail_all maps to count.
  const targetMode = uiMode === "continuous" ? "continuous" : "count";
  return {
    run_mode: fd.get("run_mode"),
    turnstile_provider: fd.get("turnstile_provider"),
    turnstile_headless: form.turnstile_headless.checked,
    target_mode: targetMode,
    target_success: Number(fd.get("target_success") || 0),
    count: Number(fd.get("count") || 1),
    workers: Number(fd.get("workers") || 1),
    local_turnstile_max_inflight: Number(fd.get("local_turnstile_max_inflight") || 8),
    local_turnstile_max_workers: Number(fd.get("local_turnstile_max_inflight") || fd.get("local_turnstile_max_workers") || 8),
    turnstile_solve_timeout: Number(fd.get("turnstile_solve_timeout") || 35),
    turnstile_solve_retries: Number(fd.get("turnstile_solve_retries") || 1),
    submit_workers: Number(fd.get("submit_workers") || 8),
    mail_code_timeout_sec: Number(fd.get("mail_code_timeout_sec") || 40),
    egress_mode: fd.get("egress_mode") || "auto",
    output_dir: fd.get("output_dir"),
    sso_convert_retries: Number(fd.get("sso_convert_retries") || 5),
    sso_convert_cooldown: Number(fd.get("sso_convert_cooldown") || 3),
    // keep UI intent for debugging / future backend use
    target_mode_ui: uiMode,
  };
}

function fillForm(data) {
  form.run_mode.value = data.run_mode || "register_otp";
  form.turnstile_provider.value = data.turnstile_provider || "local";
  form.turnstile_headless.checked = !!data.turnstile_headless;
  if (form.target_mode) {
    const savedUi = data.target_mode_ui || data.target_mode || data.run_target_mode || "count";
    // unknown values fall back to count
    const allowed = new Set(["count", "continuous", "ms_mail_all"]);
    form.target_mode.value = allowed.has(String(savedUi)) ? savedUi : "count";
  }
  if (form.target_success) form.target_success.value = data.target_success != null ? data.target_success : 0;
  form.count.value = data.count || 1;
  form.workers.value = data.workers || 1;
  if (form.local_turnstile_max_inflight) {
    form.local_turnstile_max_inflight.value =
      data.local_turnstile_max_inflight != null ? data.local_turnstile_max_inflight : 6;
  }
  if (form.turnstile_solve_timeout) {
    form.turnstile_solve_timeout.value =
      data.turnstile_solve_timeout != null ? data.turnstile_solve_timeout : 30;
  }
  if (form.turnstile_solve_retries) {
    form.turnstile_solve_retries.value =
      data.turnstile_solve_retries != null ? data.turnstile_solve_retries : 1;
  }
  if (form.submit_workers) {
    form.submit_workers.value = data.submit_workers != null ? data.submit_workers : 8;
  }
  if (form.mail_code_timeout_sec) {
    form.mail_code_timeout_sec.value =
      data.mail_code_timeout_sec != null ? data.mail_code_timeout_sec : ((data.config && data.config.mail_code_timeout_sec) || 40);
  }
  if (form.egress_mode) {
    const mode = data.egress_mode || encodeEgressMode(data.proxy_mode, data.embedded_proxy_enabled);
    form.egress_mode.value = mode || "auto";
  }
  form.output_dir.value = data.output_dir || "";
  syncEgressModeHint();
  form.sso_convert_retries.value = data.sso_convert_retries || 5;
  form.sso_convert_cooldown.value = data.sso_convert_cooldown || 3;
  $("emailProvider").textContent = "邮箱: " + (data.email_provider || (data.config && data.config.email_provider) || "-");
  syncTargetModeFields();
  if (form.target_mode && form.target_mode.value === "ms_mail_all") {
    // Refresh pool size when reloading settings in this mode.
    fillTargetFromMsMailPool({ quiet: true }).catch(() => {});
  }
}
if (form.egress_mode) {
  form.egress_mode.onchange = () => syncEgressModeHint();
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

async function fillTargetFromMsMailPool(opts = {}) {
  const quiet = !!(opts && opts.quiet);
  try {
    if (!quiet) setMsg("正在读取微软邮箱池…");
    const data = await api("/api/ms-mail-pool");
    const n = Number(data && data.line_count != null ? data.line_count : 0);
    const inv = Number(data && data.invalid_count != null ? data.invalid_count : 0);
    const path = (data && data.path) || "-";
    if (!n || n < 1) {
      if ($("msMailCountHint")) $("msMailCountHint").textContent = `池空 | ${path}`;
      if (!quiet) setMsg(`微软邮箱池有效条数为 0（${path}）。请先在配置中心写入邮箱池。`, true);
      return 0;
    }
    const mode = form.target_mode ? form.target_mode.value : "count";
    if (mode === "continuous") {
      if (form.target_success) form.target_success.value = String(n);
    } else {
      // count + ms_mail_all
      if (form.count) form.count.value = String(n);
    }
    if (form.workers) {
      const cur = Number(form.workers.value || 1);
      if (cur <= 1 && n > 1) {
        form.workers.value = String(Math.min(8, n, 128));
      } else if (cur > n) {
        form.workers.value = String(Math.min(128, n));
      }
    }
    const invPart = inv > 0 ? `，另有无效 ${inv} 行` : "";
    const modeText = mode === "continuous" ? "成功目标" : "注册数量";
    if ($("msMailCountHint")) $("msMailCountHint").textContent = `有效 ${n} 条 | ${path}`;
    if (!quiet) setMsg(`已按微软邮箱池填入 ${modeText}=${n}（${path}${invPart}）`);
    return n;
  } catch (e) {
    if (!quiet) setMsg(String(e.message || e), true);
    return 0;
  }
}

if (form.target_mode) {
  form.target_mode.onchange = async () => {
    syncTargetModeFields();
    if (form.target_mode.value === "ms_mail_all") {
      await fillTargetFromMsMailPool();
    }
  };
}

if ($("btnFillMsMailCount")) {
  $("btnFillMsMailCount").onclick = () => fillTargetFromMsMailPool();
}

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
    await refreshEgressStatusPanel();
    setMsg("配置已重载");
  } catch (e) { setMsg(String(e.message || e), true); }
};

$("btnSave").onclick = async () => {
  try {
    await api("/api/settings", { method: "PUT", body: JSON.stringify(formData()) });
    await loadSettings();
    await refreshEgressStatusPanel();
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
if ($("btnSpeedPreset8")) {
  $("btnSpeedPreset8").onclick = () => {
    if (form.workers) form.workers.value = 8;
    if (form.local_turnstile_max_inflight) form.local_turnstile_max_inflight.value = 6;
    if (form.turnstile_solve_timeout) form.turnstile_solve_timeout.value = 30;
    if (form.turnstile_solve_retries) form.turnstile_solve_retries.value = 1;
    if (form.submit_workers) form.submit_workers.value = 8;
    if (form.mail_code_timeout_sec) form.mail_code_timeout_sec.value = 40;
    if (form.turnstile_provider) form.turnstile_provider.value = "local";
    if (form.turnstile_headless) form.turnstile_headless.checked = true;
    if (form.egress_mode) {
      form.egress_mode.value = "nodes";
      syncEgressModeHint();
    }
    if (form.target_mode) form.target_mode.value = "continuous";
    if (form.target_success) form.target_success.value = 0;
    syncTargetModeFields();
    const hint = $("speedPresetHint");
    if (hint) hint.textContent = "已套用：并发8 · 同时过码6 · 过码30s · 等邮件40s · 提交8 · 只用节点池。记得保存/开始";
    setMsg("已套用 8+/分钟参数（请保存运行参数，并确保节点健康数≥8）");
  };
}
if ($("btnRefreshEgressStatus")) {
  $("btnRefreshEgressStatus").onclick = async () => {
    try {
      setMsg("正在刷新出口状态…");
      await refreshEgressStatusPanel();
      setMsg("出口状态已刷新");
    } catch (e) {
      setMsg(String(e.message || e), true);
    }
  };
}


function maskProxyUrl(raw) {
  const text = String(raw || "").trim();
  if (!text) return "-";
  try {
    return text.replace(/:\/\/([^:@\/]+):([^@\/]+)@/g, "://$1:***@");
  } catch {
    return text.slice(0, 80);
  }
}

function setEgressBadge(text, kind) {
  const badge = $("embeddedBadge");
  if (!badge) return;
  badge.textContent = text || "出口: -";
  badge.className = "badge";
  if (kind === "good") badge.classList.add("good");
  else if (kind === "warn") badge.classList.add("warn");
  else if (kind === "err") badge.classList.add("err");
}

function setEgressStatusPanel(summary, lines, badgeText, badgeKind) {
  const summaryEl = $("egressStatusSummary") || $("embeddedProxySummaryRun");
  const bodyEl = $("egressStatusBody") || $("embeddedProxyStatusRun");
  if (summaryEl) summaryEl.textContent = summary || "";
  if (bodyEl) {
    const arr = Array.isArray(lines) ? lines.filter((x) => x != null && String(x).length) : [String(lines || "")];
    bodyEl.textContent = arr.join("\n");
  }
  const oldSummary = $("embeddedProxySummaryRun");
  const oldBody = $("embeddedProxyStatusRun");
  if (oldSummary && oldSummary !== summaryEl) oldSummary.textContent = summary || "";
  if (oldBody && oldBody !== bodyEl) oldBody.textContent = Array.isArray(lines) ? lines.filter(Boolean).join("\n") : String(lines || "");
  setEgressBadge(badgeText, badgeKind);
}

function formatEmbeddedCompact(data) {
  if (!data) data = {};
  const enabled = !!data.enabled;
  const running = !!data.running;
  const phase = String(data.phase || (running ? "ready" : enabled ? "idle" : "disabled"));
  const healthy =
    data.healthy != null ? data.healthy : ((data.probe && data.probe.healthy) != null ? data.probe.healthy : "-");
  const total =
    data.total != null ? data.total : ((data.probe && data.probe.total) != null ? data.probe.total : "-");
  const leases = data.leases == null ? "-" : data.leases;
  let message = data.message || data.last_error || "";
  if (healthy !== "-" && total !== "-" && message) {
    message = String(message).replace(/健康\s*\d+\s*\/\s*\d+/g, `健康 ${healthy}/${total}`);
  }
  const phaseText = {
    starting: "启动中",
    ready: "就绪",
    error: "失败",
    disabled: "未启用",
    idle: "空闲",
  }[phase] || phase;
  const nodes = Array.isArray(data.nodes) ? data.nodes : [];
  const top = nodes.slice(0, 8).map((n, i) => {
    const name = String(n.name || n.id || "-").slice(0, 40);
    const h = n.healthy ? "Y" : "n";
    const sc = n.success_count == null ? "-" : n.success_count;
    const fc = n.fail_count == null ? "-" : n.fail_count;
    const local = n.local_http ? ` -> ${String(n.local_http).replace("http://", "")}` : "";
    return `${i + 1}. [${h}] ${name} ok=${sc} fail=${fc}${local}`;
  });
  const summary =
    `节点池: ${enabled ? "已启用" : "未启用"} | ${phaseText}` +
    ` | ${running ? "运行中" : "未运行"} | 健康 ${healthy}/${total} | 租约 ${leases}` +
    (message ? ` | ${message}` : "");
  const lines = [
    `phase=${phase} running=${running} healthy=${healthy}/${total} leases=${leases}`,
    message ? `message=${message}` : "",
    top.length ? "nodes:" : "nodes: -",
    ...top,
    nodes.length > 8 ? `... 另有 ${nodes.length - 8} 个节点` : "",
  ];
  let badgeKind = "";
  if (phase === "ready" && running) badgeKind = "good";
  else if (phase === "starting") badgeKind = "warn";
  else if (phase === "error") badgeKind = "err";
  const badge = `节点池: ${phaseText}${enabled && healthy !== "-" ? ` ${healthy}/${total}` : ""}`;
  return { summary, lines, badge, badgeKind, phase, running, healthy, total, enabled };
}

function formatHttpPoolCompact(pool, opts = {}) {
  const source = (pool && (pool.proxy_pool_source || pool.source)) || "manual";
  const sourceLabel = source === "subscription" ? "订阅导入" : "手动维护";
  const count = Number((pool && pool.line_count) || 0);
  const path = (pool && pool.path) || "fixtures/proxies.txt";
  const exists = !!(pool && pool.exists);
  const text = String((pool && pool.text) || "");
  const rows = text
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith("#"));
  const sample = rows.slice(0, 6).map((line, i) => `${i + 1}. ${maskProxyUrl(line)}`);
  const summary = `HTTP 池: ${count} 条有效 | 来源=${sourceLabel} | 文件=${exists ? "存在" : "不存在"}`;
  const lines = [
    `path=${path}`,
    `source=${sourceLabel}`,
    `valid_lines=${count}`,
    sample.length ? "samples:" : "samples: -",
    ...sample,
    rows.length > 6 ? `... 另有 ${rows.length - 6} 条` : "",
    opts.note || "",
  ];
  const badgeKind = count > 0 ? "good" : "warn";
  const badge = `HTTP池: ${count}条`;
  return { summary, lines, badge, badgeKind, count, sourceLabel, path };
}

function formatDirectCompact(proxyUrl) {
  const url = String(proxyUrl || "").trim();
  const summary = url ? "固定代理: 已配置" : "固定代理: 未填写 URL";
  const lines = [
    `proxy=${maskProxyUrl(url)}`,
    url ? "所有任务将走这个 HTTP 代理。" : "请到配置中心「注册代理」填写固定代理 URL。",
  ];
  return {
    summary,
    lines,
    badge: url ? "固定代理: 已配置" : "固定代理: 未配置",
    badgeKind: url ? "good" : "warn",
  };
}

function formatAutoCompact(proxyUrl, pool) {
  const url = String(proxyUrl || "").trim();
  if (url) {
    const d = formatDirectCompact(url);
    d.summary = "自动出口: 命中固定 URL";
    d.lines = [
      "规则: 有固定 URL 用固定，否则走 HTTP 池",
      "selected=direct",
      ...d.lines,
    ];
    d.badge = "自动: 固定URL";
    d.badgeKind = "good";
    return d;
  }
  const p = formatHttpPoolCompact(pool, { note: "规则: 未配置固定 URL，因此走 HTTP 池" });
  p.summary = `自动出口: 走 HTTP 池 | ${p.count} 条`;
  p.lines = [
    "规则: 有固定 URL 用固定，否则走 HTTP 池",
    "selected=pool",
    ...p.lines,
  ];
  p.badge = `自动: HTTP池 ${p.count}`;
  p.badgeKind = p.count > 0 ? "good" : "warn";
  return p;
}

function formatOffCompact() {
  return {
    summary: "完全关闭: 节点池和 HTTP 池都不用",
    lines: [
      "proxy_mode=none",
      "embedded_proxy_enabled=false",
      "注册请求将本机直连（不经过代理出口）。",
    ],
    badge: "出口: 关闭",
    badgeKind: "warn",
  };
}

function renderEmbeddedProxyStatus(data) {
  const fmt = formatEmbeddedCompact(data);
  setEgressStatusPanel(fmt.summary, fmt.lines, fmt.badge, fmt.badgeKind);
}

async function fetchProxyPoolLite() {
  try {
    return await api("/api/proxy-pool");
  } catch (e) {
    return {
      path: "-",
      exists: false,
      line_count: 0,
      proxy_pool_source: "manual",
      text: "",
      error: String(e.message || e),
    };
  }
}

async function fetchSettingsLite() {
  try {
    return await api("/api/settings");
  } catch {
    return {};
  }
}

async function fetchEmbeddedLite() {
  try {
    return await api("/api/embedded-proxy/status?compact=1");
  } catch (e) {
    return {
      enabled: false,
      phase: "error",
      message: String(e.message || e),
      running: false,
      healthy: 0,
      total: 0,
      leases: 0,
      nodes: [],
    };
  }
}

async function refreshEgressStatusPanel() {
  const mode = currentEgressMode();
  const title = $("egressStatusTitle");
  if (title) {
    const titles = {
      nodes: "节点池状态",
      http: "HTTP 池状态",
      hybrid: "混合出口状态",
      direct: "固定代理状态",
      auto: "自动出口状态",
      off: "出口状态",
    };
    title.textContent = titles[mode] || "出口状态";
  }

  if (mode === "off") {
    const fmt = formatOffCompact();
    setEgressStatusPanel(fmt.summary, fmt.lines, fmt.badge, fmt.badgeKind);
    return { mode, ...fmt };
  }

  if (mode === "nodes") {
    const emb = await fetchEmbeddedLite();
    const fmt = formatEmbeddedCompact(emb);
    setEgressStatusPanel(fmt.summary, fmt.lines, fmt.badge, fmt.badgeKind);
    return { mode, emb, ...fmt };
  }

  if (mode === "http") {
    const pool = await fetchProxyPoolLite();
    const fmt = formatHttpPoolCompact(pool);
    if (pool.error) fmt.lines.push(`error=${pool.error}`);
    setEgressStatusPanel(fmt.summary, fmt.lines, fmt.badge, fmt.badgeKind);
    return { mode, pool, ...fmt };
  }

  if (mode === "direct") {
    const settings = await fetchSettingsLite();
    const proxyUrl = (settings.config && settings.config.proxy) || settings.proxy || "";
    const fmt = formatDirectCompact(proxyUrl);
    setEgressStatusPanel(fmt.summary, fmt.lines, fmt.badge, fmt.badgeKind);
    return { mode, ...fmt };
  }

  if (mode === "auto") {
    const [settings, pool] = await Promise.all([fetchSettingsLite(), fetchProxyPoolLite()]);
    const proxyUrl = (settings.config && settings.config.proxy) || settings.proxy || "";
    const fmt = formatAutoCompact(proxyUrl, pool);
    setEgressStatusPanel(fmt.summary, fmt.lines, fmt.badge, fmt.badgeKind);
    return { mode, ...fmt };
  }

  // hybrid
  const [emb, pool] = await Promise.all([fetchEmbeddedLite(), fetchProxyPoolLite()]);
  const efmt = formatEmbeddedCompact(emb);
  const pfmt = formatHttpPoolCompact(pool);
  const summary = `混合: 节点 ${efmt.healthy}/${efmt.total} + HTTP ${pfmt.count} 条`;
  const lines = [
    "=== 节点池 ===",
    ...efmt.lines,
    "",
    "=== HTTP 池 ===",
    ...pfmt.lines,
    "",
    "策略: 两边轮询，一边挂了换另一边",
  ];
  let badgeKind = "good";
  const embOk = efmt.phase === "ready" && efmt.running;
  const httpOk = pfmt.count > 0;
  if (!embOk && !httpOk) badgeKind = "err";
  else if (!embOk || !httpOk) badgeKind = "warn";
  const badge = `混合: 节点${efmt.healthy}/${efmt.total} HTTP${pfmt.count}`;
  setEgressStatusPanel(summary, lines, badge, badgeKind);
  return { mode, emb, pool, summary, lines, badge, badgeKind };
}

async function refreshEmbeddedProxyStatus() {
  return refreshEgressStatusPanel();
}

let embeddedPollTimer = null;
let egressRefreshTimer = null;
function batchIsRunning() {
  const badge = $("busyBadge");
  const t = badge ? String(badge.textContent || "") : "";
  return t === "运行中" || t === "停止中" || t === "熔断暂停" || t === "补货暂停";
}
function scheduleEgressStatusRefresh(delayMs) {
  if (egressRefreshTimer) clearTimeout(egressRefreshTimer);
  egressRefreshTimer = setTimeout(() => {
    egressRefreshTimer = null;
    refreshEgressStatusPanel().catch(() => {});
  }, Math.max(0, Number(delayMs) || 0));
}
function startEmbeddedProxyPolling() {
  if (embeddedPollTimer) return;
  const tick = async () => {
    try {
      if (batchIsRunning()) {
        embeddedPollTimer = setTimeout(tick, 20000);
        return;
      }
      const data = await refreshEgressStatusPanel();
      const mode = (data && data.mode) || currentEgressMode();
      let delay = 12000;
      if (mode === "nodes" || mode === "hybrid") {
        const phase = String((data && data.emb && data.emb.phase) || (data && data.phase) || "");
        const running = !!(data && data.emb && data.emb.running) || !!(data && data.running);
        if (phase === "starting") delay = 1500;
        else if (running) delay = 4000;
        else delay = 10000;
      } else if (mode === "http" || mode === "auto") {
        delay = 15000;
      } else {
        delay = 20000;
      }
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
    try {
      await refreshEgressStatusPanel();
    } catch (_) {
      if (health.embedded_proxy) renderEmbeddedProxyStatus(health.embedded_proxy);
    }
    startEmbeddedProxyPolling();
  } catch (e) {
    setMsg(String(e.message || e), true);
    startEmbeddedProxyPolling();
  }
})();
