const $ = (id) => document.getElementById(id);
const form = $("cfgForm");
const message = $("message");
const logBox = $("logBox");
let es = null;

function setMsg(text, isError=false) {
  message.textContent = text || "";
  message.style.color = isError ? "#ff6b6b" : "#f0b429";
}

function formData() {
  const fd = new FormData(form);
  return {
    run_mode: fd.get("run_mode"),
    turnstile_provider: fd.get("turnstile_provider"),
    turnstile_headless: form.turnstile_headless.checked,
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
  form.count.value = data.count || 1;
  form.workers.value = data.workers || 1;
  form.proxy_mode.value = data.proxy_mode || "auto";
  form.output_dir.value = data.output_dir || "";
  form.sso_convert_retries.value = data.sso_convert_retries || 5;
  form.sso_convert_cooldown.value = data.sso_convert_cooldown || 3;
  $("emailProvider").textContent = "邮箱: " + (data.email_provider || (data.config && data.config.email_provider) || "-");
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

function appendLog(line) {
  logBox.textContent += line + "\n";
  const lines = logBox.textContent.split("\n");
  if (lines.length > 800) logBox.textContent = lines.slice(-800).join("\n");
  if ($("autoScroll").checked) logBox.scrollTop = logBox.scrollHeight;
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

function renderSnapshot(snap) {
  if (!snap) return;
  const total = snap.count || 0;
  const done = (snap.completed || 0);
  const pct = total ? Math.round(done * 100 / total) : 0;
  $("progressBar").style.width = pct + "%";
  const line1 = `run=${snap.run_id || "-"} | 完成 ${done}/${total} | 成功 ${snap.succeeded || 0} | 失败 ${snap.failed || 0} | 活动 ${snap.active || 0}`;
  const line2 = `速度 ${formatSpeed(snap.avg_success_per_min)} | 成功率 ${formatRate(snap.success_rate)} | 耗时 ${formatElapsed(snap.elapsed_sec)}`;
  $("progressStats").textContent = `${line1}\n${line2}`;
  const fc = snap.failure_counts || {};
  $("failureBox").textContent = Object.keys(fc).length
    ? Object.entries(fc).map(([k,v]) => `${k}: ${v}`).join("\n")
    : "-";
  const workers = snap.workers || [];
  $("workerTable").textContent = workers.length
    ? workers.map(w => `W${String(w.index).padStart(2,"0")} ${w.status} | ${w.last_log || ""}`).join("\n")
    : "-";
  const badge = $("busyBadge");
  if (snap.done) {
    badge.textContent = "已完成";
    badge.className = "badge";
    setFormDisabled(false);
  } else if (snap.started) {
    badge.textContent = snap.stopping ? "停止中" : "运行中";
    badge.className = "badge run";
    setFormDisabled(true);
  }
}

function setFormDisabled(disabled) {
  [...form.elements].forEach(el => el.disabled = disabled);
}

function connectEvents() {
  if (es) es.close();
  es = new EventSource("/api/runs/current/events");
  es.addEventListener("snapshot", (e) => renderSnapshot(JSON.parse(e.data)));
  es.addEventListener("log", (e) => {
    const data = JSON.parse(e.data);
    appendLog(data.line || "");
  });
  es.addEventListener("done", (e) => {
    renderSnapshot(JSON.parse(e.data));
    es.close();
    refreshHistory();
  });
  es.onerror = () => {
    // browser will retry; keep quiet
  };
}

async function refreshHistory() {
  const data = await api("/api/runs?limit=30");
  const box = $("historyList");
  box.innerHTML = "";
  (data.runs || []).forEach(run => {
    const div = document.createElement("div");
    div.className = "hist-item";
    div.innerHTML = `<span>${run.run_id}</span><span>成功${run.succeeded || 0}/失败${run.failed || 0}</span>`;
    div.onclick = async () => {
      const detail = await api(`/api/runs/${encodeURIComponent(run.run_id)}`);
      $("historyDetail").textContent = JSON.stringify(detail, null, 2);
    };
    box.appendChild(div);
  });
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
    appendLog("[UI] 批次启动 " + (snap.run_id || ""));
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

$("btnClearLog").onclick = () => { logBox.textContent = ""; };
$("btnRefreshHistory").onclick = () => refreshHistory().catch(e => setMsg(String(e.message || e), true));

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
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
})();
