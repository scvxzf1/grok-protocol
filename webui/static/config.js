const $ = (id) => document.getElementById(id);
const form = $("cfgCenterForm");
const msg = $("cfgMsg");

function fieldEl(name) {
  // Prefer form-associated controls (including form="cfgCenterForm" outside <form>),
  // then fall back to document-wide lookup. This keeps config-center saves stable
  // even when fields live in nested panels.
  if (form) {
    const byForm = form.elements.namedItem(name);
    if (byForm) {
      // namedItem may return a RadioNodeList; take the first concrete control.
      if (typeof byForm.length === "number" && byForm.length && !byForm.tagName) {
        return byForm[0] || null;
      }
      return byForm;
    }
  }
  return document.querySelector(`[name="${CSS && CSS.escape ? CSS.escape(name) : name}"]`) || document.getElementsByName(name)[0] || null;
}

function setMsg(text, isError=false) {
  msg.textContent = text || "";
  msg.style.color = isError ? "#ff6b6b" : "#f0b429";
}

async function api(path, opts={}) {
  const r = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const text = await r.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = { detail: text }; }
  if (!r.ok) throw new Error((body && body.detail) ? body.detail : r.statusText);
  return body;
}

function setFlag(key, hasValue) {
  const el = document.querySelector(`[data-flag="${key}"]`);
  if (el) el.textContent = hasValue ? "已从配置文件加载（可直接改，清空后保存=删除）" : "未配置";
}

function fill(data) {
  const f = data.fields || {};
  const flags = data.secret_flags || {};
  const set = (name, value, isCheck=false) => {
    const el = fieldEl(name);
    if (!el) return;
    if (isCheck) el.checked = !!value;
    else el.value = value == null ? "" : value;
  };
  set("email_provider", f.email_provider || "yyds");
  set("yyds_api_base", f.yyds_api_base || "");
  set("yyds_api_key", f.yyds_api_key || "");
  set("yyds_jwt", f.yyds_jwt || "");
  set(
    "yyds_create_spacing_sec",
    f.yyds_create_spacing_sec == null ? 1.5 : f.yyds_create_spacing_sec
  );
  set("turnstile_provider", f.turnstile_provider || "local");
  set("turnstile_api_key", f.turnstile_api_key || "");
  set("turnstile_headless", !!f.turnstile_headless, true);
  set(
    "local_turnstile_max_workers",
    f.local_turnstile_max_workers == null ? 8 : f.local_turnstile_max_workers
  );
  set(
    "submit_workers",
    f.submit_workers == null ? 8 : f.submit_workers
  );
  set(
    "turnstile_solve_timeout",
    f.turnstile_solve_timeout == null ? 90 : f.turnstile_solve_timeout
  );
  set(
    "turnstile_solve_retries",
    f.turnstile_solve_retries == null ? 1 : f.turnstile_solve_retries
  );
  set("cloudflare_api_base", f.cloudflare_api_base || "");
  set("cloudflare_api_key", f.cloudflare_api_key || "");
  set("duckmail_api_key", f.duckmail_api_key || "");
  set("ms_mail_file", f.ms_mail_file || "");
  set("proxy_mode", f.proxy_mode || "auto");
  set("proxy", f.proxy || "");
  set("proxy_file", f.proxy_file || "proxies.txt");
  set("proxy_subscription_url", f.proxy_subscription_url || "");
  set("proxy_subscription_local_http", f.proxy_subscription_local_http || "");
  set("embedded_proxy_enabled", !!f.embedded_proxy_enabled, true);
  set("embedded_proxy_binary", f.embedded_proxy_binary || "");
  set("embedded_proxy_base_port", f.embedded_proxy_base_port == null ? 28000 : f.embedded_proxy_base_port);
  set("embedded_proxy_max_nodes", f.embedded_proxy_max_nodes == null ? 50 : f.embedded_proxy_max_nodes);
  set("embedded_proxy_probe_host", f.embedded_proxy_probe_host || "accounts.x.ai");
  set("embedded_proxy_probe_port", f.embedded_proxy_probe_port == null ? 443 : f.embedded_proxy_probe_port);
  set(
    "embedded_proxy_probe_timeout_sec",
    f.embedded_proxy_probe_timeout_sec == null ? 5 : f.embedded_proxy_probe_timeout_sec
  );
  set("proxy_parent", f.proxy_parent || "");
  set("local_proxy_port", f.local_proxy_port || 17890);
  set("proxy_random", !!f.proxy_random, true);
  set("proxy_rotate_session", !!f.proxy_rotate_session, true);
  set("turnstile_proxy_enabled", !!f.turnstile_proxy_enabled, true);
  set("turnstile_proxy_mode", f.turnstile_proxy_mode || "pool");
  set("turnstile_proxy", f.turnstile_proxy || "");
  set("turnstile_proxy_file", f.turnstile_proxy_file || "turnstile_proxies.txt");
  set("turnstile_proxy_random", f.turnstile_proxy_random !== false, true);
  set("xai_oauth_output_dir", f.xai_oauth_output_dir || "");
  set("grok2api_remote_base", f.grok2api_remote_base || "");
  set("grok2api_remote_app_key", f.grok2api_remote_app_key || "");
  set("grok2api_pool_name", f.grok2api_pool_name || "");

  ["yyds_api_key","yyds_jwt","turnstile_api_key","cloudflare_api_key","duckmail_api_key","grok2api_remote_app_key"]
    .forEach(k => setFlag(k, !!flags[k] || !!(f[k] && String(f[k]).trim())));

  const pool = data.proxy_pool || {};
  $("proxyPoolText").value = pool.text || "";
  const tsPool = data.turnstile_proxy_pool || {};
  if ($("turnstileProxyPoolText")) $("turnstileProxyPoolText").value = tsPool.text || "";
  if ($("turnstilePoolMeta")) {
    $("turnstilePoolMeta").textContent = `求解代理池: ${tsPool.line_count || 0} 条 | ${tsPool.path || "-"}`;
  }
  $("poolMeta").textContent = `代理池文件: ${pool.path || "-"} | 有效行: ${pool.line_count || 0} | 存在: ${pool.exists ? "是" : "否"}`;
}

function collectFields() {
  const g = (name, isCheck=false, fallback=undefined) => {
    const el = fieldEl(name);
    if (!el) return fallback;
    if (isCheck) return !!el.checked;
    const value = el.value;
    if (value == null || value === "") {
      return fallback === undefined ? "" : fallback;
    }
    return value;
  };
  return {
    email_provider: g("email_provider"),
    yyds_api_base: g("yyds_api_base"),
    yyds_api_key: g("yyds_api_key"),
    yyds_jwt: g("yyds_jwt"),
    yyds_create_spacing_sec: Number(g("yyds_create_spacing_sec") || 1.5),
    turnstile_provider: g("turnstile_provider"),
    turnstile_api_key: g("turnstile_api_key"),
    turnstile_headless: g("turnstile_headless", true),
    local_turnstile_max_workers: Number(g("local_turnstile_max_workers") || 8),
    submit_workers: Number(g("submit_workers") || 8),
    turnstile_solve_timeout: Number(g("turnstile_solve_timeout") || 90),
    turnstile_solve_retries: Number(g("turnstile_solve_retries") || 1),
    cloudflare_api_base: g("cloudflare_api_base"),
    cloudflare_api_key: g("cloudflare_api_key"),
    duckmail_api_key: g("duckmail_api_key"),
    ms_mail_file: g("ms_mail_file"),
    proxy_mode: g("proxy_mode"),
    proxy: g("proxy"),
    proxy_file: g("proxy_file"),
    proxy_subscription_url: g("proxy_subscription_url"),
    proxy_subscription_local_http: g("proxy_subscription_local_http"),
    embedded_proxy_enabled: g("embedded_proxy_enabled", true),
    embedded_proxy_binary: g("embedded_proxy_binary"),
    embedded_proxy_base_port: Number(g("embedded_proxy_base_port") || 28000),
    embedded_proxy_max_nodes: Number(g("embedded_proxy_max_nodes") || 50),
    embedded_proxy_probe_host: g("embedded_proxy_probe_host"),
    embedded_proxy_probe_port: Number(g("embedded_proxy_probe_port") || 443),
    embedded_proxy_probe_timeout_sec: Number(g("embedded_proxy_probe_timeout_sec") || 5),
    proxy_parent: g("proxy_parent"),
    local_proxy_port: Number(g("local_proxy_port") || 17890),
    proxy_random: g("proxy_random", true),
    proxy_rotate_session: g("proxy_rotate_session", true),
    // Always emit concrete turnstile-proxy values so JSON.stringify never drops keys.
    turnstile_proxy_enabled: g("turnstile_proxy_enabled", true, false),
    turnstile_proxy_mode: g("turnstile_proxy_mode", false, "pool") || "pool",
    turnstile_proxy: g("turnstile_proxy", false, "") || "",
    turnstile_proxy_file: g("turnstile_proxy_file", false, "turnstile_proxies.txt") || "turnstile_proxies.txt",
    turnstile_proxy_random: g("turnstile_proxy_random", true, true),
    xai_oauth_output_dir: g("xai_oauth_output_dir"),
    grok2api_remote_base: g("grok2api_remote_base"),
    grok2api_remote_app_key: g("grok2api_remote_app_key"),
    grok2api_pool_name: g("grok2api_pool_name"),
  };
}

async function loadAll() {
  const data = await api("/api/config-center");
  fill(data);
  startEmbeddedStatusPolling();
}

$("btnReloadCfg").onclick = async () => {
  try {
    await api("/api/settings/reload", { method: "POST", body: "{}" });
    await loadAll();
    setMsg("已重载");
  } catch (e) { setMsg(String(e.message || e), true); }
};

function buildConfigCenterPayload() {
  return {
    fields: collectFields(),
    proxy_pool_text: ($("proxyPoolText") && $("proxyPoolText").value) || "",
    turnstile_proxy_pool_text: ($("turnstileProxyPoolText") && $("turnstileProxyPoolText").value) || "",
  };
}

$("btnSaveCfg").onclick = async () => {
  try {
    const payload = buildConfigCenterPayload();
    const data = await api("/api/config-center", { method: "PUT", body: JSON.stringify(payload) });
    fill(data);
    const ts = (data && data.fields) || {};
    const pool = (data && data.turnstile_proxy_pool) || {};
    setMsg(
      `配置已保存 | 求解代理=${ts.turnstile_proxy_enabled ? "开" : "关"}` +
      `/${ts.turnstile_proxy_mode || "pool"}` +
      ` | 求解池=${pool.line_count || 0}条`
    );
  } catch (e) { setMsg(String(e.message || e), true); }
};

$("btnSavePool").onclick = async () => {
  try {
    const data = await api("/api/proxy-pool", {
      method: "PUT",
      body: JSON.stringify({ text: $("proxyPoolText").value }),
    });
    $("poolMeta").textContent = `代理池文件: ${data.path || "-"} | 有效行: ${data.line_count || 0} | 存在: ${data.exists ? "是" : "否"}`;
    setMsg(`代理池已保存（${data.line_count || 0} 行）`);
  } catch (e) { setMsg(String(e.message || e), true); }
};


function renderSubImport(data) {
  const lines = [];
  const schemes = data.scheme_counts || {};
  const schemeText = Object.keys(schemes)
    .map((k) => `${k}:${schemes[k]}`)
    .join(", ") || "-";
  lines.push(`订阅: ${data.url || "-"}`);
  lines.push(`格式: ${data.body_kind || "-"} | 节点: ${data.node_count || 0} | 可用HTTP: ${data.usable_http_count || 0} | 跳过: ${data.skipped_count || 0}`);
  lines.push(`协议统计: ${schemeText}`);
  lines.push(`代理模式: ${data.proxy_mode || "-"} | 直连代理: ${data.proxy || "-"} | 本地回退: ${data.applied_local_http ? "是" : "否"}`);
  if ((data.warnings || []).length) {
    lines.push("");
    lines.push("警告:");
    data.warnings.forEach((w) => lines.push(`- ${w}`));
  }
  if ((data.sample_nodes || []).length) {
    lines.push("");
    lines.push("样例节点:");
    data.sample_nodes.slice(0, 8).forEach((n, idx) => {
      const flag = n.usable_http ? "http" : "need-client";
      lines.push(
        `#${idx + 1} [${flag}] ${n.scheme || "-"} ${n.name || ""} ${n.host || ""}:${n.port || 0}`.trim()
      );
    });
  }
  $("proxyTestResult").textContent = lines.join("\n");
}

$("btnImportSub").onclick = async () => {
  try {
    setMsg("正在拉取订阅…");
    $("proxyTestResult").textContent = "拉取订阅中…";
    $("btnImportSub").disabled = true;

    // 先把当前表单字段落盘，保证订阅 URL / 本地 HTTP 入口被记住。
    const saved = await api("/api/config-center", {
      method: "PUT",
      body: JSON.stringify({
        fields: collectFields(),
        proxy_pool_text: $("proxyPoolText").value,
        turnstile_proxy_pool_text: ($("turnstileProxyPoolText") && $("turnstileProxyPoolText").value) || "",
      }),
    });
    fill(saved);

    const subUrl = (fieldEl("proxy_subscription_url") || {}).value || "";
    const localHttp = (fieldEl("proxy_subscription_local_http") || {}).value || "";
    const data = await api("/api/proxy-pool/import-subscription", {
      method: "POST",
      body: JSON.stringify({
        url: subUrl,
        proxy_subscription_url: subUrl,
        proxy_subscription_local_http: localHttp,
        write_pool: true,
        use_local_http_if_empty: true,
        timeout: 20,
      }),
    });

    if (data.text != null) {
      $("proxyPoolText").value = data.text || "";
    }
    const pool = data.proxy_pool || {};
    if (pool.path || pool.line_count != null) {
      $("poolMeta").textContent = `代理池文件: ${pool.path || "-"} | 有效行: ${pool.line_count || 0} | 存在: ${pool.exists ? "是" : "否"}`;
    }
    // 刷新配置中心字段（代理模式 / 直连代理可能被回退改写）
    await loadAll();
    renderSubImport(data);

    const usable = data.usable_http_count || 0;
    const total = data.node_count || 0;
    const vlessCount = data.vless_count || (data.scheme_counts && data.scheme_counts.vless) || 0;
    const embeddedOn = !!(fieldEl("embedded_proxy_enabled") || {}).checked;
    if (usable > 0) {
      setMsg(`订阅导入完成：可用 HTTP ${usable}/${total}`);
    } else if (embeddedOn && (data.vless_for_embedded || vlessCount > 0)) {
      setMsg(`已识别 ${vlessCount || total} 个 VLESS 节点。请到下方“内嵌代理内核”点启动/重载，再预检`, true);
    } else if (data.applied_local_http) {
      setMsg(`订阅无 HTTP 节点，已回退本地入口（节点 ${total}）`, true);
    } else {
      setMsg(`订阅已拉取，但无可用 HTTP 节点（节点 ${total}）`, true);
    }
  } catch (e) {
    setMsg(String(e.message || e), true);
    $("proxyTestResult").textContent = "订阅导入失败: " + String(e.message || e);
  } finally {
    $("btnImportSub").disabled = false;
  }
};



loadAll().catch(e => setMsg(String(e.message || e), true));


function renderProxyTestTo(el, data, title) {
  if (!el) return;
  const lines = [];
  lines.push(`${title || "代理池测试"}`);
  lines.push(`探测: ${data.probe_url || data.url || "-"} | 超时: ${data.timeout_sec || data.timeout || "-"}s`);
  lines.push(`来源: ${data.source || "-"} ${data.source_path || ""}`.trim());
  const total = data.total_available != null ? data.total_available : (data.total || 0);
  const tested = data.tested != null ? data.tested : ((data.results || []).length);
  const ok = data.ok != null ? data.ok : (data.success || 0);
  const fail = data.fail != null ? data.fail : (data.failed != null ? data.failed : Math.max(0, tested - ok));
  lines.push(`池内可用: ${total} | 本次测试: ${tested} | 成功: ${ok} | 失败: ${fail}`);
  lines.push("");
  (data.results || []).forEach((item) => {
    const status = item.ok ? "OK" : "FAIL";
    const latency = item.latency_ms == null ? "-" : `${item.latency_ms}ms`;
    const ip = item.exit_ip || item.ip || "-";
    const err = item.error ? ` | ${item.error}` : "";
    lines.push(`[${status}] #${item.index} ${item.display || item.proxy || "-"} | ${latency} | ip=${ip}${err}`);
  });
  if (!(data.results || []).length) {
    lines.push("没有可测试的代理行（可能都是注释或为空）。");
  }
  el.textContent = lines.join("\n");
}

function summarizePoolTest(data) {
  if (!data || data.error) return { tested: 0, ok: 0, fail: 0, error: (data && data.error) || "unknown" };
  const tested = data.tested != null ? data.tested : ((data.results || []).length);
  const ok = data.ok != null ? data.ok : (data.success || 0);
  const fail = data.fail != null ? data.fail : (data.failed != null ? data.failed : Math.max(0, tested - ok));
  return { tested, ok, fail, error: "" };
}

$("btnTestPool").onclick = async () => {
  const regBox = $("proxyTestResult");
  const tsBox = $("turnstileProxyTestResult");
  try {
    setMsg("正在同步测试：注册代理池 + 求解代理池…");
    if (regBox) regBox.textContent = "注册代理池测试中…";
    if (tsBox) tsBox.textContent = "求解代理池测试中…";
    $("btnTestPool").disabled = true;

    const bodyReg = {
      count: 5,
      timeout: 12,
      text: ($("proxyPoolText") && $("proxyPoolText").value) || "",
    };
    const bodyTs = {
      count: 5,
      timeout: 12,
      text: ($("turnstileProxyPoolText") && $("turnstileProxyPoolText").value) || "",
    };

    const [regRes, tsRes] = await Promise.allSettled([
      api("/api/proxy-pool/test", { method: "POST", body: JSON.stringify(bodyReg) }),
      api("/api/turnstile-proxy-pool/test", { method: "POST", body: JSON.stringify(bodyTs) }),
    ]);

    let regData = null;
    let tsData = null;
    if (regRes.status === "fulfilled") {
      regData = regRes.value || {};
      renderProxyTestTo(regBox, regData, "【注册代理池】");
    } else {
      const err = String((regRes.reason && regRes.reason.message) || regRes.reason || "测试失败");
      if (regBox) regBox.textContent = "【注册代理池】\n测试失败: " + err;
      regData = { error: err, tested: 0, ok: 0, fail: 0 };
    }
    if (tsRes.status === "fulfilled") {
      tsData = tsRes.value || {};
      renderProxyTestTo(tsBox, tsData, "【求解代理池】");
    } else {
      const err = String((tsRes.reason && tsRes.reason.message) || tsRes.reason || "测试失败");
      if (tsBox) tsBox.textContent = "【求解代理池】\n测试失败: " + err;
      tsData = { error: err, tested: 0, ok: 0, fail: 0 };
    }

    const a = summarizePoolTest(regData);
    const b = summarizePoolTest(tsData);
    const parts = [
      `注册池 ${a.ok}/${a.tested}`,
      `求解池 ${b.ok}/${b.tested}`,
    ];
    const hardFail = !!(a.error || b.error);
    setMsg(`双池测试完成：${parts.join(" | ")}` + (hardFail ? "（有一侧失败，见下方反馈）" : ""), hardFail && (a.tested + b.tested) === 0);
  } catch (e) {
    setMsg(String(e.message || e), true);
    if (regBox) regBox.textContent = "测试失败: " + String(e.message || e);
    if (tsBox) tsBox.textContent = "测试失败: " + String(e.message || e);
  } finally {
    $("btnTestPool").disabled = false;
  }
};




function renderEmbeddedStatus(data) {
  const box = $("embeddedProxyStatus");
  const summary = $("embeddedProxySummary");
  if (!box) return;
  data = data || {};
  const enabled = !!data.enabled;
  const running = !!data.running;
  const phase = String(data.phase || (running ? "ready" : enabled ? "idle" : "disabled"));
  const healthy = data.healthy == null ? "-" : data.healthy;
  const total = data.total == null ? "-" : data.total;
  const leases = data.leases == null ? "-" : data.leases;
  const lastError = data.last_error || "";
  const message = data.message || lastError || "";
  const phaseText = {
    starting: "启动中",
    ready: "就绪",
    error: "失败",
    disabled: "未启用",
    idle: "空闲",
  }[phase] || phase;
  if (summary) {
    summary.textContent =
      `状态: ${enabled ? "已启用" : "未启用"} | ${phaseText} | ${running ? "运行中" : "未运行"} | 健康 ${healthy}/${total} | 租约 ${leases}` +
      (message ? ` | ${message}` : "");
  }
  try {
    box.textContent = JSON.stringify(data, null, 2);
  } catch {
    box.textContent = String(data);
  }
}

async function refreshEmbeddedStatus() {
  const data = await api("/api/embedded-proxy/status");
  renderEmbeddedStatus(data || {});
  return data;
}

let embeddedStatusTimer = null;
function startEmbeddedStatusPolling() {
  if (embeddedStatusTimer) return;
  const tick = async () => {
    try {
      const data = await refreshEmbeddedStatus();
      const phase = String((data && data.phase) || "");
      const delay = phase === "starting" ? 1200 : 5000;
      embeddedStatusTimer = setTimeout(tick, delay);
    } catch (e) {
      renderEmbeddedStatus({
        enabled: false,
        phase: "error",
        message: String(e.message || e),
        running: false,
        healthy: 0,
        total: 0,
        leases: 0,
      });
      embeddedStatusTimer = setTimeout(tick, 5000);
    }
  };
  tick();
}

const btnEmbeddedStart = $("btnEmbeddedStart");
if (btnEmbeddedStart) {
  btnEmbeddedStart.onclick = async () => {
    try {
      setMsg("正在启动/重载内嵌代理…");
      btnEmbeddedStart.disabled = true;
      // 先保存当前表单，避免用旧配置启动
      const saved = await api("/api/config-center", {
        method: "PUT",
        body: JSON.stringify(buildConfigCenterPayload()),
      });
      fill(saved);
      const data = await api("/api/embedded-proxy/reload", { method: "POST", body: "{}" });
      renderEmbeddedStatus(data || {});
      setMsg(`内嵌代理已启动/重载：健康 ${(data && data.healthy) || 0}/${(data && data.total) || 0}`);
    } catch (e) {
      setMsg(String(e.message || e), true);
    } finally {
      btnEmbeddedStart.disabled = false;
    }
  };
}

const btnEmbeddedProbe = $("btnEmbeddedProbe");
if (btnEmbeddedProbe) {
  btnEmbeddedProbe.onclick = async () => {
    try {
      setMsg("正在预检内嵌节点…");
      btnEmbeddedProbe.disabled = true;
      const data = await api("/api/embedded-proxy/probe", { method: "POST", body: "{}" });
      renderEmbeddedStatus(data || {});
      setMsg(`预检完成：健康 ${(data && data.healthy) || 0}/${(data && data.total) || 0}`);
    } catch (e) {
      setMsg(String(e.message || e), true);
    } finally {
      btnEmbeddedProbe.disabled = false;
    }
  };
}

const btnEmbeddedStatus = $("btnEmbeddedStatus");
if (btnEmbeddedStatus) {
  btnEmbeddedStatus.onclick = async () => {
    try {
      setMsg("正在刷新内嵌代理状态…");
      btnEmbeddedStatus.disabled = true;
      await refreshEmbeddedStatus();
      setMsg("状态已刷新");
    } catch (e) {
      setMsg(String(e.message || e), true);
    } finally {
      btnEmbeddedStatus.disabled = false;
    }
  };
}

const btnEmbeddedStop = $("btnEmbeddedStop");
if (btnEmbeddedStop) {
  btnEmbeddedStop.onclick = async () => {
    try {
      setMsg("正在停止内嵌代理…");
      btnEmbeddedStop.disabled = true;
      const data = await api("/api/embedded-proxy/stop", { method: "POST", body: "{}" });
      renderEmbeddedStatus(data || {});
      setMsg("内嵌代理已停止");
    } catch (e) {
      setMsg(String(e.message || e), true);
    } finally {
      btnEmbeddedStop.disabled = false;
    }
  };
}


function setupHelpTips() {
  const tips = Array.from(document.querySelectorAll(".help-tip"));
  if (!tips.length) return;

  const closeAll = (except = null) => {
    tips.forEach((btn) => {
      if (btn !== except) btn.classList.remove("is-open");
    });
  };

  tips.forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const willOpen = !btn.classList.contains("is-open");
      closeAll();
      if (willOpen) btn.classList.add("is-open");
    });
  });

  document.addEventListener("click", () => closeAll());
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeAll();
  });
}




if ($("btnSaveTurnstilePool")) {
  $("btnSaveTurnstilePool").onclick = async () => {
    try {
      const data = await api("/api/turnstile-proxy-pool", {
        method: "PUT",
        body: JSON.stringify({ text: ($("turnstileProxyPoolText") && $("turnstileProxyPoolText").value) || "" }),
      });
      if ($("turnstilePoolMeta")) {
        $("turnstilePoolMeta").textContent = `求解代理池: ${data.line_count || 0} 条 | ${data.path || "-"}`;
      }
      setMsg(`求解代理池已保存：${data.line_count || 0} 条`);
    } catch (e) {
      setMsg(String(e.message || e), true);
    }
  };
}

setupHelpTips();


