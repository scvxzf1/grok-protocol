const $ = (id) => document.getElementById(id);

function configForm() {
  return $("cfgCenterForm");
}

function fieldEl(name) {
  // Prefer form-associated controls (including form="cfgCenterForm" outside <form>),
  // then fall back to document-wide lookup. This keeps config-center saves stable
  // even when fields live in nested panels.
  const form = configForm();
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
  const msg = $("cfgMsg");
  if (!msg) return;
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
    "local_turnstile_max_inflight",
    f.local_turnstile_max_inflight == null ? 8 : f.local_turnstile_max_inflight
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
  set("proxy_file", f.proxy_file || "fixtures/proxies.txt");
  set("proxy_pool_source", f.proxy_pool_source || "manual");
  const subUrls = Array.isArray(f.proxy_subscription_urls)
    ? f.proxy_subscription_urls
    : String(f.proxy_subscription_urls || f.proxy_subscription_url || "")
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
  set(
    "proxy_subscription_urls",
    subUrls.length ? subUrls.join("\n") : (f.proxy_subscription_url || "")
  );
  set("proxy_subscription_local_http", f.proxy_subscription_local_http || "");
  set("embedded_proxy_enabled", !!f.embedded_proxy_enabled, true);
  set("embedded_proxy_binary", f.embedded_proxy_binary || "");
  set("embedded_proxy_listen_host", f.embedded_proxy_listen_host || "127.0.0.1");
  set("embedded_proxy_base_port", f.embedded_proxy_base_port == null ? 28000 : f.embedded_proxy_base_port);
  set("embedded_proxy_max_nodes", f.embedded_proxy_max_nodes == null ? 50 : f.embedded_proxy_max_nodes);
  set("embedded_proxy_probe_host", f.embedded_proxy_probe_host || "accounts.x.ai");
  set("embedded_proxy_probe_port", f.embedded_proxy_probe_port == null ? 443 : f.embedded_proxy_probe_port);
  set(
    "embedded_proxy_probe_timeout_sec",
    f.embedded_proxy_probe_timeout_sec == null ? 5 : f.embedded_proxy_probe_timeout_sec
  );
  set(
    "embedded_proxy_max_node_retries",
    f.embedded_proxy_max_node_retries == null ? 3 : f.embedded_proxy_max_node_retries
  );
  set("local_proxy_port", f.local_proxy_port || 17890);
  set("proxy_random", !!f.proxy_random, true);
  set("proxy_rotate_session", !!f.proxy_rotate_session, true);
  set("turnstile_proxy_enabled", !!f.turnstile_proxy_enabled, true);
  set("turnstile_proxy_mode", f.turnstile_proxy_mode || "pool");
  set("turnstile_proxy", f.turnstile_proxy || "");
  set("turnstile_proxy_file", f.turnstile_proxy_file || "fixtures/turnstile_proxies.txt");
  set("turnstile_proxy_random", f.turnstile_proxy_random !== false, true);
  set("xai_oauth_output_dir", f.xai_oauth_output_dir || "");
  set("cpa_api_url", f.cpa_api_url || "");
  set("cpa_api_key", f.cpa_api_key || "");
  set("cpa_auto_upload", !!f.cpa_auto_upload, true);
  set("cpa_use_local_name", f.cpa_use_local_name !== false, true);
  set("cpa_skip_duplicates", f.cpa_skip_duplicates !== false, true);

  ["yyds_api_key","yyds_jwt","turnstile_api_key","cloudflare_api_key","duckmail_api_key","cpa_api_key"]
    .forEach(k => setFlag(k, !!flags[k] || !!(f[k] && String(f[k]).trim())));
  // Mark which secrets were loaded non-empty so empty-save only clears intentional edits.
  ["yyds_api_key","yyds_jwt","turnstile_api_key","cloudflare_api_key","duckmail_api_key","cpa_api_key"].forEach((k) => {
    const el = fieldEl(k);
    if (!el) return;
    const has = !!(f[k] && String(f[k]).trim()) || !!flags[k];
    el.dataset.secretLoaded = has ? "1" : "0";
    el.dataset.secretTouched = "0";
    if (!el.dataset.secretBound) {
      el.dataset.secretBound = "1";
      el.addEventListener("input", () => { el.dataset.secretTouched = "1"; });
      el.addEventListener("change", () => { el.dataset.secretTouched = "1"; });
    }
  });


  const pool = data.proxy_pool || {};
  const poolText = pool.text || "";
  if ($("proxyPoolText")) $("proxyPoolText").value = poolText;
  if ($("proxyPoolTextPreview")) $("proxyPoolTextPreview").value = poolText;
  const tsPool = data.turnstile_proxy_pool || {};
  if ($("turnstileProxyPoolText")) $("turnstileProxyPoolText").value = tsPool.text || "";
  if ($("turnstilePoolMeta")) {
    $("turnstilePoolMeta").textContent = `求解代理池: ${tsPool.line_count || 0} 条 | ${tsPool.path || "-"}`;
  }
  if ($("poolMeta")) {
    $("poolMeta").textContent = `代理池文件: ${pool.path || "-"} | 有效行: ${pool.line_count || 0} | 存在: ${pool.exists ? "是" : "否"}`;
  }
  const msPool = data.ms_mail_pool || {};
  if ($("msMailPoolText")) $("msMailPoolText").value = msPool.text || "";
  if ($("msMailPoolMeta")) {
    const inv = msPool.invalid_count ? ` | 无效: ${msPool.invalid_count}` : "";
    $("msMailPoolMeta").textContent = `微软邮箱池: ${msPool.path || "-"} | 有效: ${msPool.line_count || 0}${inv} | 存在: ${msPool.exists ? "是" : "否"}`;
  }
  applyProxyPoolSourceUI(f.proxy_pool_source || "manual");
  updateEgressModeUI();
}

function collectFields() {
  // Only include fields present on the current page, so split config pages
  // never wipe values that live on other pages.
  const present = (name) => !!fieldEl(name);
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
  const out = {};
  const put = (name, value) => {
    if (present(name)) out[name] = value;
  };
  const putSecret = (name) => {
    if (!present(name)) return;
    const el = fieldEl(name);
    const value = g(name, false, "");
    const text = value == null ? "" : String(value);
    // Preserve existing secret unless the field was touched.
    // - loaded empty + still empty => omit (no-op)
    // - loaded set + untouched empty (shouldn't happen after fill) => omit
    // - touched empty => clear
    // - any non-empty => set
    if (text.trim()) {
      out[name] = text.trim();
      return;
    }
    if (el && el.dataset && el.dataset.secretTouched === "1") {
      out[name] = ""; // explicit clear
      return;
    }
    // omit => backend keeps previous
  };
  put("email_provider", g("email_provider"));
  put("yyds_api_base", g("yyds_api_base"));
  putSecret("yyds_api_key");
  putSecret("yyds_jwt");
  if (present("yyds_create_spacing_sec")) put("yyds_create_spacing_sec", Number(g("yyds_create_spacing_sec") || 1.5));
  put("turnstile_provider", g("turnstile_provider"));
  putSecret("turnstile_api_key");
  if (present("turnstile_headless")) put("turnstile_headless", g("turnstile_headless", true));
  if (present("local_turnstile_max_workers")) put("local_turnstile_max_workers", Number(g("local_turnstile_max_workers") || 8));
  if (present("local_turnstile_max_inflight")) put("local_turnstile_max_inflight", Number(g("local_turnstile_max_inflight") || 8));
  if (present("submit_workers")) put("submit_workers", Number(g("submit_workers") || 8));
  if (present("turnstile_solve_timeout")) put("turnstile_solve_timeout", Number(g("turnstile_solve_timeout") || 90));
  if (present("turnstile_solve_retries")) put("turnstile_solve_retries", Number(g("turnstile_solve_retries") || 1));
  put("cloudflare_api_base", g("cloudflare_api_base"));
  putSecret("cloudflare_api_key");
  putSecret("duckmail_api_key");
  put("ms_mail_file", g("ms_mail_file"));
  put("proxy_mode", g("proxy_mode"));
  put("proxy", g("proxy"));
  put("proxy_file", g("proxy_file"));
  if (present("proxy_pool_source")) put("proxy_pool_source", g("proxy_pool_source", false, "manual") || "manual");
  put("proxy_subscription_urls", g("proxy_subscription_urls"));
  put("proxy_subscription_local_http", g("proxy_subscription_local_http"));
  if (present("embedded_proxy_enabled")) put("embedded_proxy_enabled", g("embedded_proxy_enabled", true));
  put("embedded_proxy_binary", g("embedded_proxy_binary"));
  put("embedded_proxy_listen_host", g("embedded_proxy_listen_host"));
  if (present("embedded_proxy_base_port")) put("embedded_proxy_base_port", Number(g("embedded_proxy_base_port") || 28000));
  if (present("embedded_proxy_max_nodes")) {
    const rawMaxNodes = g("embedded_proxy_max_nodes");
    const maxNodes = rawMaxNodes === "" || rawMaxNodes == null ? 50 : Number(rawMaxNodes);
    put("embedded_proxy_max_nodes", Number.isFinite(maxNodes) ? maxNodes : 50);
  }
  put("embedded_proxy_probe_host", g("embedded_proxy_probe_host"));
  if (present("embedded_proxy_probe_port")) put("embedded_proxy_probe_port", Number(g("embedded_proxy_probe_port") || 443));
  if (present("embedded_proxy_probe_timeout_sec")) put("embedded_proxy_probe_timeout_sec", Number(g("embedded_proxy_probe_timeout_sec") || 5));
  if (present("embedded_proxy_max_node_retries")) put("embedded_proxy_max_node_retries", Number(g("embedded_proxy_max_node_retries") || 3));
  if (present("local_proxy_port")) put("local_proxy_port", Number(g("local_proxy_port") || 17890));
  if (present("proxy_random")) put("proxy_random", g("proxy_random", true));
  if (present("proxy_rotate_session")) put("proxy_rotate_session", g("proxy_rotate_session", true));
  if (present("turnstile_proxy_enabled")) put("turnstile_proxy_enabled", g("turnstile_proxy_enabled", true, false));
  if (present("turnstile_proxy_mode")) put("turnstile_proxy_mode", g("turnstile_proxy_mode", false, "pool") || "pool");
  if (present("turnstile_proxy")) put("turnstile_proxy", g("turnstile_proxy", false, "") || "");
  if (present("turnstile_proxy_file")) put("turnstile_proxy_file", g("turnstile_proxy_file", false, "fixtures/turnstile_proxies.txt") || "fixtures/turnstile_proxies.txt");
  if (present("turnstile_proxy_random")) put("turnstile_proxy_random", g("turnstile_proxy_random", true, true));
  put("xai_oauth_output_dir", g("xai_oauth_output_dir"));
  put("cpa_api_url", g("cpa_api_url"));
  putSecret("cpa_api_key");
  if (present("cpa_auto_upload")) put("cpa_auto_upload", g("cpa_auto_upload", true, false));
  if (present("cpa_use_local_name")) put("cpa_use_local_name", g("cpa_use_local_name", true, true));
  if (present("cpa_skip_duplicates")) put("cpa_skip_duplicates", g("cpa_skip_duplicates", true, true));
  return out;
}

async function loadAll() {
  const data = await api("/api/config-center");
  fill(data);
  startEmbeddedStatusPolling();
  if ($("embeddedNodeCacheText")) {
    try { await loadEmbeddedNodeCacheEditor(); } catch (_) { /* ignore */ }
  }
}

if ($("btnReloadCfg")) $("btnReloadCfg").onclick = async () => {
  try {
    await api("/api/settings/reload", { method: "POST", body: "{}" });
    await loadAll();
    setMsg("已重载");
  } catch (e) { setMsg(String(e.message || e), true); }
};

function buildConfigCenterPayload() {
  const source = currentProxyPoolSource();
  const payload = {
    fields: collectFields(),
  };
  // Only submit pool texts when the corresponding editors exist on this page.
  if ($("turnstileProxyPoolText")) {
    payload.turnstile_proxy_pool_text = $("turnstileProxyPoolText").value || "";
  }
  if ($("msMailPoolText")) {
    payload.ms_mail_pool_text = $("msMailPoolText").value || "";
  }
  // 仅手动维护时提交注册池文本；订阅模式由「拉取订阅」写入，避免保存配置误覆盖。
  if ($("proxyPoolText") && source === "manual") {
    payload.proxy_pool_text = $("proxyPoolText").value || "";
  }
  return payload;
}

function currentProxyPoolSource() {
  const el = fieldEl("proxy_pool_source");
  const v = el && el.value ? String(el.value).trim().toLowerCase() : "manual";
  return v === "subscription" ? "subscription" : "manual";
}

function applyProxyPoolSourceUI(source) {
  // 二选一：同一时刻只展示其中一个面板（CSS data-attr + hidden 双保险）。
  const mode = (source === "subscription") ? "subscription" : "manual";
  const col = document.querySelector(".proxy-col-reg");
  const manualPanel = $("regSourceManual");
  const subPanel = $("regSourceSubscription");
  const poolText = $("proxyPoolText");
  const savePool = $("btnSavePool");
  const importBtn = $("btnImportSub");
  const sourceSelect = fieldEl("proxy_pool_source") || $("proxyPoolSource");

  if (col) col.setAttribute("data-active-pool-source", mode);
  if (sourceSelect && sourceSelect.value !== mode) {
    sourceSelect.value = mode;
  }

  if (manualPanel) {
    const show = mode === "manual";
    manualPanel.hidden = !show;
    if (show) {
      manualPanel.style.removeProperty("display");
    } else {
      manualPanel.style.display = "none";
    }
    manualPanel.setAttribute("aria-hidden", show ? "false" : "true");
  }
  if (subPanel) {
    const show = mode === "subscription";
    subPanel.hidden = !show;
    if (show) {
      subPanel.style.removeProperty("display");
    } else {
      subPanel.style.display = "none";
    }
    subPanel.setAttribute("aria-hidden", show ? "false" : "true");
  }

  if (poolText) poolText.readOnly = mode !== "manual";
  if (savePool) savePool.disabled = mode !== "manual";
  if (importBtn) importBtn.disabled = mode !== "subscription";
  document.querySelectorAll("#proxySourceTabs [data-pool-source]").forEach((btn) => {
    btn.classList.toggle("is-active", btn.getAttribute("data-pool-source") === mode);
  });
}

if ($("btnSaveCfg")) $("btnSaveCfg").onclick = async () => {
  try {
    const payload = buildConfigCenterPayload();
    const data = await api("/api/config-center", { method: "PUT", body: JSON.stringify(payload) });
    fill(data);
    const fields = (data && data.fields) || {};
    const regPool = (data && data.proxy_pool) || {};
    const tsPool = (data && data.turnstile_proxy_pool) || {};
    const sourceLabel = (fields.proxy_pool_source === "subscription") ? "订阅导入" : "手动维护";
    updateEgressModeUI();
    setMsg(
      `配置已保存 | 出口=${describeEgressMode(fields)}` +
      ` | 池来源=${sourceLabel}` +
      ` | 注册池 ${regPool.line_count || 0} 条` +
      ` | 求解代理=${fields.turnstile_proxy_enabled ? "开" : "关"}/${fields.turnstile_proxy_mode || "pool"}` +
      ` | 求解池 ${tsPool.line_count || 0} 条`
    );
  } catch (e) { setMsg(String(e.message || e), true); }
};

if ($("btnSavePool")) $("btnSavePool").onclick = async () => {
  try {
    if (currentProxyPoolSource() !== "manual") {
      setMsg("当前为「订阅导入」来源，请先切换为「手动维护」再保存池内容", true);
      return;
    }
    const data = await api("/api/proxy-pool", {
      method: "PUT",
      body: JSON.stringify({ text: $("proxyPoolText").value }),
    });
    if ($("poolMeta")) {
      $("poolMeta").textContent = `代理池文件: ${data.path || "-"} | 有效行: ${data.line_count || 0} | 存在: ${data.exists ? "是" : "否"}`;
    }
    if ($("proxyPoolTextPreview")) $("proxyPoolTextPreview").value = $("proxyPoolText").value || "";
    setMsg(`注册代理池已保存（${data.line_count || 0} 行）`);
  } catch (e) { setMsg(String(e.message || e), true); }
};


function renderSubImport(data) {
  const lines = [];
  const schemes = data.scheme_counts || {};
  const schemeText = Object.keys(schemes)
    .map((k) => `${k}:${schemes[k]}`)
    .join(", ") || "-";
  const urls = Array.isArray(data.urls) && data.urls.length
    ? data.urls
    : (data.url ? [data.url] : []);
  lines.push(`订阅: ${urls.length ? urls.join(" | ") : "-"}`);
  lines.push(`格式: ${data.body_kind || "-"} | 节点: ${data.node_count || 0} | 可用HTTP: ${data.usable_http_count || 0} | 跳过: ${data.skipped_count || 0}`);
  lines.push(`协议统计: ${schemeText}`);
  lines.push(`池来源: ${data.proxy_pool_source || "subscription"} | 代理模式: ${data.proxy_mode || "-"} | 直连代理: ${data.proxy || "-"} | 本地回退: ${data.applied_local_http ? "是" : "否"}`);
  if ((data.per_url || []).length) {
    lines.push("");
    lines.push("各链接:");
    data.per_url.forEach((u, idx) => {
      if (u.ok) {
        lines.push(
          `#${idx + 1} ok nodes=${u.node_count || 0} http=${u.usable_http || 0} kind=${u.body_kind || "-"} ${u.url || ""}`
        );
      } else {
        lines.push(`#${idx + 1} FAIL ${u.error || "error"} ${u.url || ""}`);
      }
    });
  }
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
  const box = $("proxySubImportResult") || $("proxyTestResult");
  if (box) box.textContent = lines.join("\n");
}

if ($("btnImportSub")) $("btnImportSub").onclick = async () => {
  try {
    if (currentProxyPoolSource() !== "subscription") {
      setMsg("当前为「手动维护」来源，请先切换为「订阅导入」再拉取", true);
      return;
    }
    setMsg("正在拉取订阅…");
    const importBox = $("proxySubImportResult") || $("proxyTestResult");
    if (importBox) importBox.textContent = "拉取订阅中…";
    if ($("btnImportSub")) $("btnImportSub").disabled = true;

    // 先把当前表单字段落盘（含 source=subscription），保证订阅 URL / 本地 HTTP 入口被记住。
    const saved = await api("/api/config-center", {
      method: "PUT",
      body: JSON.stringify(buildConfigCenterPayload()),
    });
    fill(saved);

    const subUrls = (fieldEl("proxy_subscription_urls") || {}).value || "";
    const localHttp = (fieldEl("proxy_subscription_local_http") || {}).value || "";
    const data = await api("/api/proxy-pool/import-subscription", {
      method: "POST",
      body: JSON.stringify({
        proxy_subscription_urls: subUrls,
        proxy_subscription_local_http: localHttp,
        write_pool: true,
        use_local_http_if_empty: true,
        timeout: 20,
      }),
    });

    if (data.text != null) {
      if ($("proxyPoolText")) $("proxyPoolText").value = data.text || "";
      if ($("proxyPoolTextPreview")) $("proxyPoolTextPreview").value = data.text || "";
    }
    const pool = data.proxy_pool || {};
    if ($("poolMeta") && (pool.path || pool.line_count != null)) {
      $("poolMeta").textContent = `代理池文件: ${pool.path || "-"} | 有效行: ${pool.line_count || 0} | 存在: ${pool.exists ? "是" : "否"}`;
    }
    // 刷新配置中心字段（代理模式 / 直连代理可能被回退改写）
    await loadAll();
    // loadAll 会刷新池预览；再写回本次导入日志，避免被“尚未拉取”初始态盖住。
    if (data.text != null) {
      if ($("proxyPoolText")) $("proxyPoolText").value = data.text || "";
      if ($("proxyPoolTextPreview")) $("proxyPoolTextPreview").value = data.text || "";
    }
    renderSubImport(data);

    const usable = data.usable_http_count || 0;
    const total = data.node_count || 0;
    const vlessCount = data.vless_count || (data.scheme_counts && data.scheme_counts.vless) || 0;
    const embeddedOn = !!(fieldEl("embedded_proxy_enabled") || {}).checked;
    if (usable > 0) {
      setMsg(`订阅导入完成：可用 HTTP ${usable}/${total}`);
    } else if (embeddedOn && (data.vless_for_embedded || vlessCount > 0)) {
      setMsg(`已识别 ${vlessCount || total} 个 VLESS 节点。请到左列“内嵌 mihomo”先拉取订阅节点，再启动/重载`, true);
    } else if (data.applied_local_http) {
      setMsg(`订阅无 HTTP 节点，已回退本地入口（节点 ${total}）`, true);
    } else {
      setMsg(`订阅已拉取，但无可用 HTTP 节点（节点 ${total}）`, true);
    }
  } catch (e) {
    setMsg(String(e.message || e), true);
    const importBox = $("proxySubImportResult") || $("proxyTestResult");
    if (importBox) importBox.textContent = "订阅导入失败: " + String(e.message || e);
  } finally {
    applyProxyPoolSourceUI(currentProxyPoolSource());
    if ($("btnImportSub")) $("btnImportSub").disabled = currentProxyPoolSource() !== "subscription";
  }
};



try { loadAll().catch(e => setMsg(String(e.message || e), true)); } catch (e) { setMsg(String(e.message || e), true); }


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

if ($("btnTestPool")) $("btnTestPool").onclick = async () => {
  const regBox = $("proxyTestResult");
  const tsBox = $("turnstileProxyTestResult");
  const hasReg = !!regBox;
  const hasTs = !!tsBox;
  try {
    const labels = [];
    if (hasReg) labels.push("注册代理池");
    if (hasTs) labels.push("求解代理池");
    setMsg(labels.length ? `正在测试：${labels.join(" + ")}…` : "当前页没有可测试的代理池");
    if (regBox) regBox.textContent = "注册代理池测试中…";
    if (tsBox) tsBox.textContent = "求解代理池测试中…";
    if ($("btnTestPool")) $("btnTestPool").disabled = true;

    const tasks = [];
    const taskKinds = [];
    if (hasReg) {
      taskKinds.push("reg");
      tasks.push(api("/api/proxy-pool/test", {
        method: "POST",
        body: JSON.stringify({
          count: 5,
          timeout: 12,
          text: ($("proxyPoolText") && $("proxyPoolText").value) || "",
        }),
      }));
    }
    if (hasTs) {
      taskKinds.push("ts");
      tasks.push(api("/api/turnstile-proxy-pool/test", {
        method: "POST",
        body: JSON.stringify({
          count: 5,
          timeout: 12,
          text: ($("turnstileProxyPoolText") && $("turnstileProxyPoolText").value) || "",
        }),
      }));
    }
    const settled = tasks.length ? await Promise.allSettled(tasks) : [];
    let regRes = { status: "rejected", reason: new Error("本页无注册代理池") };
    let tsRes = { status: "rejected", reason: new Error("本页无求解代理池") };
    settled.forEach((res, idx) => {
      if (taskKinds[idx] === "reg") regRes = res;
      if (taskKinds[idx] === "ts") tsRes = res;
    });

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

    const parts = [];
    let hardFail = false;
    let testedSum = 0;
    if (hasReg) {
      const a = summarizePoolTest(regData);
      parts.push(`注册池 ${a.ok}/${a.tested}`);
      hardFail = hardFail || !!a.error;
      testedSum += a.tested || 0;
    }
    if (hasTs) {
      const b = summarizePoolTest(tsData);
      parts.push(`求解池 ${b.ok}/${b.tested}`);
      hardFail = hardFail || !!b.error;
      testedSum += b.tested || 0;
    }
    setMsg(
      (parts.length ? `测试完成：${parts.join(" | ")}` : "当前页没有可测试的代理池")
        + (hardFail ? "（有失败，见下方反馈）" : ""),
      hardFail && testedSum === 0
    );
  } catch (e) {
    setMsg(String(e.message || e), true);
    if (regBox) regBox.textContent = "测试失败: " + String(e.message || e);
    if (tsBox) tsBox.textContent = "测试失败: " + String(e.message || e);
  } finally {
    if ($("btnTestPool")) $("btnTestPool").disabled = false;
  }
};




function renderEmbeddedStatus(data, opts) {
  const box = $("embeddedProxyStatus");
  const summary = $("embeddedProxySummary");
  if (!box) return;
  data = data || {};
  opts = opts || {};
  const enabled = !!data.enabled;
  const running = !!data.running;
  const phase = String(data.phase || (running ? "ready" : enabled ? "idle" : "disabled"));
  // Prefer top-level healthy/total; fall back to nested probe payload.
  const probe = data.probe || {};
  const healthy =
    data.healthy != null ? data.healthy : (probe.healthy != null ? probe.healthy : "-");
  const total =
    data.total != null ? data.total : (probe.total != null ? probe.total : "-");
  const leases = data.leases == null ? "-" : data.leases;
  const lastError = data.last_error || "";
  let message = data.message || lastError || "";
  // 摘要数字与 message 内旧「健康 x/y」冲突时，去掉 message 里的重复片段，避免看起来没刷新
  if (healthy !== "-" && total !== "-" && message) {
    message = String(message)
      .replace(/健康\s*\d+\s*\/\s*\d+/g, `健康 ${healthy}/${total}`)
      .replace(/运行中\s*健康\s*\d+\s*\/\s*\d+/g, `运行中 健康 ${healthy}/${total}`);
  }
  const cache = data.cache || {};
  const cacheCount = cache.count != null ? cache.count : null;
  const cacheTime = cache.mtime_text || "";
  const phaseText = {
    starting: "启动中",
    ready: "就绪",
    error: "失败",
    disabled: "未启用",
    idle: "空闲",
  }[phase] || phase;
  if (summary) {
    let cachePart = "";
    if (cacheCount != null) {
      cachePart = ` | 缓存节点 ${cacheCount}` + (cacheTime ? ` @ ${cacheTime}` : "");
    }
    summary.textContent =
      `状态: ${enabled ? "已启用" : "未启用"} | ${phaseText} | ${running ? "运行中" : "未运行"} | 健康 ${healthy}/${total} | 租约 ${leases}` +
      cachePart +
      (message ? ` | ${message}` : "");
  }
  // 默认紧凑渲染：全量 nodes JSON 会卡顿，导致「健康数好像不刷新」
  const full = !!opts.full;
  try {
    if (full) {
      box.textContent = JSON.stringify(data, null, 2);
      return;
    }
    const nodes = Array.isArray(data.nodes) ? data.nodes : [];
    const byProto = (cache && cache.by_protocol) || data.cached_by_protocol || {};
    const top = nodes.slice(0, 12).map((n, i) => {
      const name = String((n && (n.name || n.id)) || "-").slice(0, 48);
      const h = n && n.healthy ? "Y" : "n";
      const sc = n && n.success_count != null ? n.success_count : "-";
      const fc = n && n.fail_count != null ? n.fail_count : "-";
      const lat = n && n.last_latency_ms != null ? `${n.last_latency_ms}ms` : "-";
      return `${i + 1}. [${h}] ${name} ok=${sc} fail=${fc} lat=${lat}`;
    });
    const lines = [
      `phase=${phase} running=${running} healthy=${healthy}/${total} leases=${leases}`,
      message ? `message=${message}` : "",
      cacheCount != null ? `cache=${cacheCount}` + (cacheTime ? ` @ ${cacheTime}` : "") : "",
      Object.keys(byProto).length
        ? `cache_by_protocol=${Object.keys(byProto).map((k) => `${k}:${byProto[k]}`).join(",")}`
        : "",
      top.length ? "nodes(top):" : "nodes: -",
      ...top,
      nodes.length > 12 ? `... 另有 ${nodes.length - 12} 个节点（点「刷新状态」看完整 JSON）` : "",
    ].filter(Boolean);
    box.textContent = lines.join("\n");
  } catch {
    box.textContent = String(data);
  }
}

async function refreshEmbeddedStatus(opts) {
  const data = await api("/api/embedded-proxy/status");
  renderEmbeddedStatus(data || {}, opts || {});
  return data;
}

let embeddedStatusTimer = null;
let embeddedPollGen = 0;
function startEmbeddedStatusPolling() {
  if (embeddedStatusTimer) return;
  const tick = async () => {
    const gen = ++embeddedPollGen;
    try {
      const data = await refreshEmbeddedStatus();
      if (gen !== embeddedPollGen) return;
      const phase = String((data && data.phase) || "");
      const running = !!(data && data.running);
      // 启动中/刚运行时加快刷新，便于健康数及时变化
      let delay = 5000;
      if (phase === "starting") delay = 1000;
      else if (running) delay = 2500;
      embeddedStatusTimer = setTimeout(tick, delay);
    } catch (e) {
      if (gen !== embeddedPollGen) return;
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

function bumpEmbeddedStatusPoll(delayMs) {
  // 操作后立刻再刷一次，并允许新一轮 tick 覆盖旧 timer
  if (embeddedStatusTimer) {
    clearTimeout(embeddedStatusTimer);
    embeddedStatusTimer = null;
  }
  embeddedPollGen += 1;
  const wait = Math.max(200, Number(delayMs) || 400);
  embeddedStatusTimer = setTimeout(() => {
    embeddedStatusTimer = null;
    startEmbeddedStatusPolling();
  }, wait);
}


async function loadEmbeddedNodeCacheEditor() {
  const box = $("embeddedNodeCacheText");
  const meta = $("embeddedCacheMeta");
  if (!box && !meta) return null;
  try {
    const data = await api("/api/embedded-proxy/node-cache");
    if (box) box.value = data.text || "";
    if (meta) {
      meta.textContent = `缓存: ${data.path || "-"} | 节点行: ${data.line_count || 0} | 存在: ${data.exists ? "是" : "否"}`;
    }
    return data;
  } catch (e) {
    if (meta) meta.textContent = `缓存读取失败: ${String(e.message || e)}`;
    throw e;
  }
}

async function saveEmbeddedNodeCacheEditor() {
  const box = $("embeddedNodeCacheText");
  if (!box) throw new Error("当前页没有节点缓存编辑框");
  const data = await api("/api/embedded-proxy/node-cache", {
    method: "PUT",
    body: JSON.stringify({ text: box.value || "" }),
  });
  if (box && data.text != null) box.value = data.text;
  const meta = $("embeddedCacheMeta");
  if (meta) {
    meta.textContent = `缓存: ${data.path || "-"} | 节点行: ${data.line_count || 0} | 存在: 是`;
  }
  return data;
}

async function clearEmbeddedNodeCacheEditor() {
  const data = await api("/api/embedded-proxy/node-cache", { method: "DELETE" });
  const box = $("embeddedNodeCacheText");
  if (box) box.value = data.text || "";
  const meta = $("embeddedCacheMeta");
  if (meta) meta.textContent = `缓存: ${data.path || "-"} | 节点行: 0 | 已清空`;
  return data;
}

async function clearProxyPoolEditor({ save = true } = {}) {
  if ($("proxyPoolText")) $("proxyPoolText").value = "";
  if ($("proxyPoolTextPreview")) $("proxyPoolTextPreview").value = "";
  if (!save) return { line_count: 0 };
  // 切到手动后保存空池
  const src = fieldEl("proxy_pool_source");
  if (src) src.value = "manual";
  applyProxyPoolSourceUI("manual");
  const data = await api("/api/proxy-pool", {
    method: "PUT",
    body: JSON.stringify({ text: "" }),
  });
  if ($("poolMeta")) {
    $("poolMeta").textContent = `代理池文件: ${data.path || "-"} | 有效行: 0 | 存在: ${data.exists ? "是" : "否"}`;
  }
  return data;
}

const btnEmbeddedFetchSub = $("btnEmbeddedFetchSub");
if (btnEmbeddedFetchSub) {
  btnEmbeddedFetchSub.onclick = async () => {
    try {
      setMsg("正在拉取订阅节点（仅写缓存，不启动）…");
      btnEmbeddedFetchSub.disabled = true;
      const saved = await api("/api/config-center", {
        method: "PUT",
        body: JSON.stringify(buildConfigCenterPayload()),
      });
      fill(saved);
      const subUrls = (fieldEl("proxy_subscription_urls") || {}).value || "";
      const data = await api("/api/embedded-proxy/fetch-subscription", {
        method: "POST",
        body: JSON.stringify({
          proxy_subscription_urls: subUrls,
          timeout: 20,
        }),
      });
      const count =
        (data && (data.cached_node_count != null ? data.cached_node_count : data.cached_vless_count)) || 0;
      setMsg(String((data && data.message) || `已缓存内嵌节点 ${count} 个`));
      // 先用拉取结果渲染（含 cache/message），再拉 status；status 会覆盖但不应再是「缓存为空」。
      if (data) {
        renderEmbeddedStatus({
          enabled: !!(fieldEl("embedded_proxy_enabled") || {}).checked,
          running: false,
          phase: data.phase || "idle",
          message: data.message || "",
          healthy: 0,
          total: 0,
          leases: 0,
          cache: data.cache || {},
          cached_node_count: count,
          cached_by_protocol: data.cached_by_protocol || {},
        });
      }
      try {
        await refreshEmbeddedStatus();
      } catch (_) {
        /* ignore */
      }
      try { await loadEmbeddedNodeCacheEditor(); } catch (_) { /* ignore */ }
      bumpEmbeddedStatusPoll(1000);
    } catch (e) {
      setMsg(String(e.message || e), true);
    } finally {
      btnEmbeddedFetchSub.disabled = false;
    }
  };
}

const btnEmbeddedStart = $("btnEmbeddedStart");
if (btnEmbeddedStart) {
  btnEmbeddedStart.onclick = async () => {
    try {
      setMsg("正在启动/重载内嵌代理（使用缓存节点，不拉订阅）…");
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
      bumpEmbeddedStatusPoll(600);
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
      // probe 现在返回完整 status 字段；直接渲染，避免只显示 results 数组
      renderEmbeddedStatus(data || {});
      const h = (data && data.healthy) != null ? data.healthy : ((data && data.probe && data.probe.healthy) || 0);
      const t = (data && data.total) != null ? data.total : ((data && data.probe && data.probe.total) || 0);
      setMsg(`预检完成：健康 ${h}/${t}`);
      bumpEmbeddedStatusPoll(800);
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
      // 手动刷新给完整 JSON，便于排查
      await refreshEmbeddedStatus({ full: true });
      setMsg("状态已刷新");
      bumpEmbeddedStatusPoll(2000);
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
      bumpEmbeddedStatusPoll(800);
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
  if ($("btnSaveTurnstilePool")) $("btnSaveTurnstilePool").onclick = async () => {
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


// ---- Microsoft mail pool + alias split/backfill (from GPT register UI) ----
function setMsMailMeta(data) {
  if (!$("msMailPoolMeta")) return;
  const inv = data && data.invalid_count ? ` | 无效: ${data.invalid_count}` : "";
  $("msMailPoolMeta").textContent = `微软邮箱池: ${(data && data.path) || "-"} | 有效: ${(data && data.line_count) || 0}${inv} | 存在: ${data && data.exists ? "是" : "否"}`;
}

function setMsAliasStatus(message, level = "") {
  const el = $("msAliasStatus");
  if (!el) return;
  el.textContent = message || "";
  el.className = `tool-status ${level || ""}`.trim();
}

function openMsAliasTool() {
  const modal = $("msAliasModal");
  if (!modal) return;
  if (!$("msAliasSource").value.trim() && $("msMailPoolText") && $("msMailPoolText").value.trim()) {
    $("msAliasSource").value = $("msMailPoolText").value.trim();
  }
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function closeMsAliasTool() {
  const modal = $("msAliasModal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

const MS_ALIAS_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const MS_ALIAS_DELIM = "----";
const MS_ALIAS_MAIL_RE = /([a-zA-Z0-9._%+-]+)@(hotmail|outlook|live)\.com/i;

function splitMsColonLine(line) {
  const segments = String(line).split(":");
  if (segments.length < 4) return null;
  const [email, password, clientId, ...tokenParts] = segments;
  return [email, password, clientId, tokenParts.join(":")];
}

function parseMsAliasLine(line) {
  if (line.includes(MS_ALIAS_DELIM)) {
    return { parts: line.split(MS_ALIAS_DELIM).map((p) => p.trim()), format: "dash" };
  }
  const colonParts = splitMsColonLine(line);
  if (colonParts) {
    return { parts: colonParts.map((p) => p.trim()), format: "colon" };
  }
  return { parts: [String(line || "").trim()], format: "plain" };
}

function parseMsHotmail(value) {
  const match = String(value || "").trim().match(MS_ALIAS_MAIL_RE);
  return match ? `${match[1]}@${match[2].toLowerCase()}.com` : "";
}

function msRandomLetters(n) {
  let t = "";
  for (let i = 0; i < n; i += 1) t += MS_ALIAS_LETTERS[Math.floor(Math.random() * MS_ALIAS_LETTERS.length)];
  return t;
}

function buildMsAliases(baseEmail, count, usedSet, rule) {
  const at = baseEmail.lastIndexOf("@");
  const local = baseEmail.slice(0, at);
  const domain = baseEmail.slice(at + 1);
  const aliases = [];
  if (rule === "sequential") {
    for (let i = 1; i <= count; i += 1) {
      const alias = `${local}+${i}@${domain}`;
      usedSet.add(alias.toLowerCase());
      aliases.push(alias);
    }
    return aliases;
  }
  for (let i = 0; i < count; i += 1) {
    let alias = "";
    let tries = 0;
    do {
      alias = `${local}+${msRandomLetters(6)}@${domain}`;
      tries += 1;
    } while (usedSet.has(alias.toLowerCase()) && tries < 50);
    usedSet.add(alias.toLowerCase());
    aliases.push(alias);
  }
  return aliases;
}

function formatMsAliasOutput(alias, parts, keepFields) {
  const extras = [];
  if (keepFields && parts.length > 1) extras.push(...parts.slice(1));
  return extras.length ? [alias, ...extras].join(MS_ALIAS_DELIM) : alias;
}

function clampMsAliasCount(raw) {
  const n = Number.parseInt(raw, 10);
  if (Number.isNaN(n)) return 5;
  return Math.max(1, Math.min(20, n));
}

function generateMsAliasResult() {
  const lines = ($("msAliasSource").value || "").split(/\r?\n/);
  const count = clampMsAliasCount($("msAliasCount") && $("msAliasCount").value);
  const keepFields = !($("msAliasKeepFields") && !$("msAliasKeepFields").checked);
  const includePrimary = !!( $("msAliasIncludePrimary") && $("msAliasIncludePrimary").checked );
  const removeUsed = !!( $("msAliasRemoveUsed") && $("msAliasRemoveUsed").checked );
  const stagger = !!( $("msAliasStagger") && $("msAliasStagger").checked );
  const rule = ($("msAliasRule") && $("msAliasRule").value) || "random";
  const usedSet = new Set();
  const validRecords = [];
  const remaining = [];
  const outputs = [];
  let validRows = 0;
  let skipped = 0;
  let removed = 0;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      if (removeUsed) remaining.push(rawLine);
      continue;
    }
    const { parts } = parseMsAliasLine(line);
    const baseEmail = parseMsHotmail(parts[0] || line);
    if (!baseEmail) {
      skipped += 1;
      if (removeUsed) remaining.push(rawLine);
      continue;
    }
    validRows += 1;
    if (removeUsed) removed += 1;
    validRecords.push({
      baseEmail,
      aliases: buildMsAliases(baseEmail, count, usedSet, rule),
      parts,
    });
  }

  if (stagger) {
    for (let i = 0; i < count; i += 1) {
      for (const rec of validRecords) {
        const alias = rec.aliases[i];
        if (alias) outputs.push(formatMsAliasOutput(alias, rec.parts, keepFields));
      }
    }
  } else {
    for (const rec of validRecords) {
      for (const alias of rec.aliases) {
        outputs.push(formatMsAliasOutput(alias, rec.parts, keepFields));
      }
    }
  }
  if (includePrimary) {
    for (const rec of validRecords) {
      outputs.push(formatMsAliasOutput(rec.baseEmail, rec.parts, keepFields));
    }
  }
  if (removeUsed) $("msAliasSource").value = remaining.join("\n");
  $("msAliasResult").value = outputs.join("\n");
  if (!outputs.length) {
    setMsAliasStatus("没有生成任何结果。请确认输入含 @hotmail.com / @outlook.com / @live.com。", "warn");
    return;
  }
  setMsAliasStatus(
    [
      `生成完成，共 ${outputs.length} 条。`,
      `有效邮箱 ${validRows} 行，跳过 ${skipped} 行。`,
      removeUsed ? `已从输入移除 ${removed} 行。` : "已保留原输入。",
      stagger ? "输出：错开顺序。" : "输出：按邮箱连续。",
      rule === "sequential" ? "规则：顺序 +1/+2…" : "规则：随机字母。",
    ].join("\n"),
    "ok"
  );
}

function convertMsAliasColonToDash() {
  const lines = ($("msAliasSource").value || "").split(/\r?\n/);
  let n = 0;
  const out = lines.map((raw) => {
    const line = raw.trim();
    if (!line) return raw;
    const colon = splitMsColonLine(line);
    if (colon && parseMsHotmail(colon[0])) {
      n += 1;
      return colon.map((x) => x.trim()).join(MS_ALIAS_DELIM);
    }
    return raw;
  });
  $("msAliasSource").value = out.join("\n");
  setMsAliasStatus(n ? `已转换 ${n} 行冒号格式为 ----。` : "没有找到可转换的冒号格式。", n ? "ok" : "warn");
}

function applyMsAliasResultToPool() {
  const text = ($("msAliasResult").value || "").trim();
  if (!text) {
    setMsAliasStatus("当前没有可回填的结果。", "warn");
    return;
  }
  if ($("msMailPoolText")) $("msMailPoolText").value = text;
  setMsAliasStatus("结果已回填到「微软邮箱池」编辑框。请再点「仅保存邮箱池」写入文件。", "ok");
}

async function copyMsAliasResult() {
  const text = ($("msAliasResult").value || "").trim();
  if (!text) {
    setMsAliasStatus("当前没有可复制的结果。", "warn");
    return;
  }
  try {
    if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
    else {
      $("msAliasResult").focus();
      $("msAliasResult").select();
      document.execCommand("copy");
    }
    setMsAliasStatus("已复制到剪贴板。", "ok");
  } catch (_) {
    setMsAliasStatus("复制失败，请手动全选。", "err");
  }
}

function downloadMsAliasResult() {
  const text = ($("msAliasResult").value || "").trim();
  if (!text) {
    setMsAliasStatus("当前没有可下载的结果。", "warn");
    return;
  }
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "ms_mail_aliases.txt";
  a.click();
  URL.revokeObjectURL(url);
  setMsAliasStatus("已开始下载 ms_mail_aliases.txt。", "ok");
}

if ($("btnSaveMsMailPool")) {
  if ($("btnSaveMsMailPool")) $("btnSaveMsMailPool").onclick = async () => {
    try {
      const data = await api("/api/ms-mail-pool", {
        method: "PUT",
        body: JSON.stringify({ text: ($("msMailPoolText") && $("msMailPoolText").value) || "" }),
      });
      setMsMailMeta(data || {});
      if ($("msMailPoolText") && data && typeof data.text === "string") {
        $("msMailPoolText").value = data.text;
      }
      if (data && data.path && fieldEl("ms_mail_file")) {
        fieldEl("ms_mail_file").value = data.path;
      }
      const inv = data && data.invalid_count ? `，无效 ${data.invalid_count} 行` : "";
      setMsg(`微软邮箱池已保存：有效 ${data.line_count || 0} 条${inv}`);
    } catch (e) {
      setMsg(String(e.message || e), true);
    }
  };
}
if ($("btnOpenMsAlias")) $("btnOpenMsAlias").onclick = () => openMsAliasTool();
if ($("btnCloseMsAlias")) $("btnCloseMsAlias").onclick = () => closeMsAliasTool();
if ($("btnMsAliasGenerate")) $("btnMsAliasGenerate").onclick = () => generateMsAliasResult();
if ($("btnMsAliasColon")) $("btnMsAliasColon").onclick = () => convertMsAliasColonToDash();
if ($("btnMsAliasApply")) $("btnMsAliasApply").onclick = () => applyMsAliasResultToPool();
if ($("btnMsAliasCopy")) $("btnMsAliasCopy").onclick = () => copyMsAliasResult();
if ($("btnMsAliasDownload")) $("btnMsAliasDownload").onclick = () => downloadMsAliasResult();
if ($("btnMsAliasClear")) {
  if ($("btnMsAliasClear")) $("btnMsAliasClear").onclick = () => {
    if ($("msAliasSource")) $("msAliasSource").value = "";
    if ($("msAliasResult")) $("msAliasResult").value = "";
    setMsAliasStatus("已清空，等待新的输入。");
  };
}
if ($("btnMsAliasDemo")) {
  if ($("btnMsAliasDemo")) $("btnMsAliasDemo").onclick = () => {
    $("msAliasSource").value = [
      "alice@hotmail.com----pass001----00000000-0000-0000-0000-000000000001----M.C_token_a",
      "bob@outlook.com:pass002:00000000-0000-0000-0000-000000000002:M.C_token_b",
    ].join("\n");
    setMsAliasStatus("示例已填充，可点「生成结果」。");
  };
}
if ($("msAliasModal")) {
  $("msAliasModal").addEventListener("click", (ev) => {
    if (ev.target === $("msAliasModal")) closeMsAliasTool();
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeMsAliasTool();
  });
}



function clearSubscriptionUrlsEditor({ save = false } = {}) {
  const el = fieldEl("proxy_subscription_urls") || $("proxySubscriptionUrls");
  if (el) el.value = "";
  return { cleared: true, save: !!save };
}

if ($("btnClearSubUrls")) {
  $("btnClearSubUrls").onclick = () => {
    clearSubscriptionUrlsEditor({ save: false });
    setMsg("订阅链接已清空（仅当前输入框；要落盘请点顶部「保存配置」，或点「清空订阅并保存」）");
  };
}

if ($("btnClearSubUrlsAndSave")) {
  $("btnClearSubUrlsAndSave").onclick = async () => {
    try {
      clearSubscriptionUrlsEditor({ save: true });
      setMsg("正在清空订阅并保存…");
      const payload = buildConfigCenterPayload();
      const saved = await api("/api/config-center", {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      fill(saved);
      setMsg("订阅链接已清空并保存");
    } catch (e) {
      setMsg(String(e.message || e), true);
    }
  };
}

if ($("btnLoadEmbeddedCache")) {
  $("btnLoadEmbeddedCache").onclick = async () => {
    try {
      setMsg("正在读取节点缓存…");
      const data = await loadEmbeddedNodeCacheEditor();
      setMsg(`节点缓存已加载：${(data && data.line_count) || 0} 条`);
    } catch (e) {
      setMsg(String(e.message || e), true);
    }
  };
}

if ($("btnSaveEmbeddedCache")) {
  $("btnSaveEmbeddedCache").onclick = async () => {
    try {
      setMsg("正在保存节点缓存…");
      const data = await saveEmbeddedNodeCacheEditor();
      setMsg(String((data && data.message) || `节点缓存已保存：${(data && data.line_count) || 0} 条`));
      try { await refreshEmbeddedStatus(); } catch (_) {}
    } catch (e) {
      setMsg(String(e.message || e), true);
    }
  };
}

if ($("btnClearEmbeddedCache")) {
  $("btnClearEmbeddedCache").onclick = async () => {
    if (!window.confirm("确认清空节点缓存？这不会自动停止已运行的 mihomo，但下次启动会没有节点。")) return;
    try {
      setMsg("正在清空节点缓存…");
      const data = await clearEmbeddedNodeCacheEditor();
      setMsg(String((data && data.message) || "节点缓存已清空"));
      try { await refreshEmbeddedStatus(); } catch (_) {}
    } catch (e) {
      setMsg(String(e.message || e), true);
    }
  };
}

if ($("btnClearProxyPool") || $("btnClearProxyPoolManual")) {
  const clearHandler = async () => {
    if (!window.confirm("确认清空 HTTP 代理池文件？")) return;
    try {
      setMsg("正在清空 HTTP 代理池…");
      const data = await clearProxyPoolEditor({ save: true });
      setMsg(`HTTP 代理池已清空（${(data && data.line_count) || 0} 条）`);
    } catch (e) {
      setMsg(String(e.message || e), true);
    }
  };
  if ($("btnClearProxyPool")) $("btnClearProxyPool").onclick = clearHandler;
  if ($("btnClearProxyPoolManual")) $("btnClearProxyPoolManual").onclick = clearHandler;
}

// 页面有节点缓存编辑框时，自动加载一次
if ($("embeddedNodeCacheText")) {
  loadEmbeddedNodeCacheEditor().catch(() => {});
}

setupHelpTips();

// 同步初始化一次，避免等 API 返回前两块都露出来
applyProxyPoolSourceUI(currentProxyPoolSource());

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

function decodeEgressMode(preset) {
  const p = String(preset || "").toLowerCase();
  if (p === "nodes") return { proxy_mode: "none", embedded_proxy_enabled: true };
  if (p === "http") return { proxy_mode: "pool", embedded_proxy_enabled: false };
  if (p === "hybrid") return { proxy_mode: "pool", embedded_proxy_enabled: true };
  if (p === "direct") return { proxy_mode: "direct", embedded_proxy_enabled: false };
  if (p === "auto") return { proxy_mode: "auto", embedded_proxy_enabled: false };
  if (p === "off") return { proxy_mode: "none", embedded_proxy_enabled: false };
  return null;
}

function describeEgressMode(fields) {
  const mode = String((fields && fields.proxy_mode) || (fieldEl("proxy_mode") || {}).value || "auto").toLowerCase();
  const emb = !!(fields && Object.prototype.hasOwnProperty.call(fields, "embedded_proxy_enabled")
    ? fields.embedded_proxy_enabled
    : (fieldEl("embedded_proxy_enabled") || {}).checked);
  const preset = encodeEgressMode(mode, emb);
  const labels = {
    nodes: "只用节点池",
    http: "只用 HTTP 池",
    hybrid: "一起用",
    direct: "固定一个",
    auto: "自动",
    off: "完全关闭",
  };
  return labels[preset] || preset || "未知";
}

function setPanelHidden(el, hidden) {
  if (!el) return;
  el.hidden = !!hidden;
  el.style.display = hidden ? "none" : "";
  el.setAttribute("aria-hidden", hidden ? "true" : "false");
}

function syncAdvancedMirrorsFromHidden() {
  const map = [
    ["proxyModeSelectVisible", "proxy_mode", "value"],
    ["embeddedProxyEnabledVisible", "embedded_proxy_enabled", "checked"],
    ["proxyFileVisible", "proxy_file", "value"],
    ["proxyRetriesVisible", "embedded_proxy_max_node_retries", "value"],
    ["localProxyPortVisible", "local_proxy_port", "value"],
    ["proxyRandomVisible", "proxy_random", "checked"],
    ["proxyRotateVisible", "proxy_rotate_session", "checked"],
    ["embeddedBinaryVisible", "embedded_proxy_binary", "value"],
    ["embeddedListenVisible", "embedded_proxy_listen_host", "value"],
    ["embeddedBasePortVisible", "embedded_proxy_base_port", "value"],
    ["embeddedMaxNodesVisible", "embedded_proxy_max_nodes", "value"],
    ["embeddedProbeHostVisible", "embedded_proxy_probe_host", "value"],
    ["embeddedProbePortVisible", "embedded_proxy_probe_port", "value"],
    ["embeddedProbeTimeoutVisible", "embedded_proxy_probe_timeout_sec", "value"],
    ["subLocalHttpVisible", "proxy_subscription_local_http", "value"],
  ];
  map.forEach(([visibleId, name, prop]) => {
    const vis = $(visibleId);
    const hid = fieldEl(name);
    if (!vis || !hid) return;
    if (prop === "checked") vis.checked = !!hid.checked;
    else vis.value = hid.value == null ? "" : hid.value;
  });
}

function bindAdvancedMirrors() {
  const pairs = [
    ["proxyModeSelectVisible", "proxy_mode", "value", "change"],
    ["embeddedProxyEnabledVisible", "embedded_proxy_enabled", "checked", "change"],
    ["proxyFileVisible", "proxy_file", "value", "input"],
    ["proxyRetriesVisible", "embedded_proxy_max_node_retries", "value", "input"],
    ["localProxyPortVisible", "local_proxy_port", "value", "input"],
    ["proxyRandomVisible", "proxy_random", "checked", "change"],
    ["proxyRotateVisible", "proxy_rotate_session", "checked", "change"],
    ["embeddedBinaryVisible", "embedded_proxy_binary", "value", "input"],
    ["embeddedListenVisible", "embedded_proxy_listen_host", "value", "input"],
    ["embeddedBasePortVisible", "embedded_proxy_base_port", "value", "input"],
    ["embeddedMaxNodesVisible", "embedded_proxy_max_nodes", "value", "input"],
    ["embeddedProbeHostVisible", "embedded_proxy_probe_host", "value", "input"],
    ["embeddedProbePortVisible", "embedded_proxy_probe_port", "value", "input"],
    ["embeddedProbeTimeoutVisible", "embedded_proxy_probe_timeout_sec", "value", "input"],
    ["subLocalHttpVisible", "proxy_subscription_local_http", "value", "input"],
  ];
  pairs.forEach(([visibleId, name, prop, evt]) => {
    const vis = $(visibleId);
    const hid = fieldEl(name);
    if (!vis || !hid || vis.dataset.boundMirror === "1") return;
    vis.dataset.boundMirror = "1";
    vis.addEventListener(evt, () => {
      if (prop === "checked") hid.checked = !!vis.checked;
      else hid.value = vis.value;
      if (name === "proxy_mode" || name === "embedded_proxy_enabled") updateEgressModeUI();
    });
  });
}

function updateEgressModeUI() {
  const modeEl = fieldEl("proxy_mode");
  const embEl = fieldEl("embedded_proxy_enabled");
  const mode = String((modeEl && modeEl.value) || "auto").toLowerCase();
  const emb = !!(embEl && embEl.checked);
  const preset = encodeEgressMode(mode, emb);
  document.querySelectorAll("[data-egress-preset]").forEach((btn) => {
    btn.classList.toggle("is-active", btn.getAttribute("data-egress-preset") === preset);
  });
  const label = describeEgressMode({ proxy_mode: mode, embedded_proxy_enabled: emb });
  const tips = {
    nodes: "注册只走右边节点池。左边 HTTP 池可先不管。",
    http: "注册只走左边代理列表。先保证有 http:// 行。",
    hybrid: "两边轮着用，一边挂了换另一边。",
    direct: "所有任务都用上面的固定 URL。",
    auto: "有固定 URL 就用固定，否则走 HTTP 池；默认不启节点池。",
    off: "节点池和 HTTP 池都关掉，相当于本机直连。",
  };
  const detailMap = {
    nodes: "proxy_mode=none + 节点池开",
    http: "proxy_mode=pool + 节点池关",
    hybrid: "proxy_mode=pool + 节点池开",
    direct: "proxy_mode=direct + 节点池关",
    auto: "proxy_mode=auto + 节点池关",
    off: "proxy_mode=none + 节点池关",
  };
  const hint = $("egressModeHint");
  if (hint) hint.textContent = `当前：${label}。${tips[preset] || ""}`;
  const detail = $("egressModeDetail");
  if (detail) detail.textContent = `组合：${detailMap[preset] || (mode + " / emb=" + emb)}`;

  // 面板显隐：按 6 种出口独立控制
  setPanelHidden($("httpPoolPanel"), !(preset === "http" || preset === "hybrid" || preset === "auto"));
  setPanelHidden($("directProxyPanel"), preset !== "direct" && preset !== "auto");
  setPanelHidden($("nodePoolPanel"), !(preset === "nodes" || preset === "hybrid"));
  if (preset === "off") {
    setPanelHidden($("httpPoolPanel"), true);
    setPanelHidden($("directProxyPanel"), true);
    setPanelHidden($("nodePoolPanel"), true);
  }

  const httpHint = $("httpPoolHint");
  if (httpHint) {
    if (preset === "hybrid") httpHint.textContent = "混合模式：这里是 HTTP 侧。也可把右边健康节点一键写进来。";
    else if (preset === "http") httpHint.textContent = "只用 HTTP 池：在这里粘贴或订阅导入。";
    else if (preset === "auto") httpHint.textContent = "自动模式：没填固定 URL 时，会用这里的 HTTP 池。";
    else httpHint.textContent = "一行一个代理。VLESS 别写这里。";
  }
  const nodeHint = $("nodePoolHint");
  if (nodeHint) {
    if (preset === "nodes") {
      nodeHint.textContent = "只用节点池：填订阅 → 拉节点/手改缓存 → 启动。订阅和节点都能改、都能一键清空。";
    } else if (preset === "hybrid") {
      nodeHint.textContent = "混合模式：节点池这边负责协议节点；需要时也可把健康节点写到左边 HTTP 池。";
    } else {
      nodeHint.textContent = "三步：填订阅 → 拉节点 / 手改缓存 → 启动。订阅和节点都能改、都能一键清空。";
    }
  }
  // 只用节点池时，不必强调「写 HTTP 池」
  setPanelHidden($("nodeToHttpSyncActions"), preset === "nodes" || preset === "off");
  syncAdvancedMirrorsFromHidden();
}

function applyEgressPreset(preset) {
  const modeEl = fieldEl("proxy_mode");
  const embEl = fieldEl("embedded_proxy_enabled");
  if (!modeEl || !embEl) {
    setMsg("当前页没有出口配置控件", true);
    return;
  }
  const decoded = decodeEgressMode(preset);
  if (!decoded) {
    setMsg("未知出口预设", true);
    return;
  }
  modeEl.value = decoded.proxy_mode;
  embEl.checked = !!decoded.embedded_proxy_enabled;
  updateEgressModeUI();
  setMsg(`已切换：${describeEgressMode()}（再点顶部「保存配置」）`);
}

function bindSimplePoolSourceTabs() {
  const tabs = Array.from(document.querySelectorAll("#proxySourceTabs [data-pool-source]"));
  if (!tabs.length) return;
  const sourceEl = fieldEl("proxy_pool_source") || $("proxyPoolSource");
  const paint = () => {
    const mode = currentProxyPoolSource();
    tabs.forEach((btn) => btn.classList.toggle("is-active", btn.getAttribute("data-pool-source") === mode));
  };
  tabs.forEach((btn) => {
    if (btn.dataset.boundTab === "1") return;
    btn.dataset.boundTab = "1";
    btn.addEventListener("click", () => {
      const mode = btn.getAttribute("data-pool-source") === "subscription" ? "subscription" : "manual";
      if (sourceEl) sourceEl.value = mode;
      applyProxyPoolSourceUI(mode);
      paint();
    });
  });
  paint();
}

document.querySelectorAll("[data-egress-preset]").forEach((btn) => {
  btn.addEventListener("click", () => applyEgressPreset(btn.getAttribute("data-egress-preset")));
});
const proxyModeEl = fieldEl("proxy_mode");
if (proxyModeEl) proxyModeEl.addEventListener("change", updateEgressModeUI);
const embEnableEl = fieldEl("embedded_proxy_enabled");
if (embEnableEl) embEnableEl.addEventListener("change", updateEgressModeUI);
bindAdvancedMirrors();
bindSimplePoolSourceTabs();
updateEgressModeUI();

const proxyPoolSourceEl = fieldEl("proxy_pool_source") || $("proxyPoolSource");
if (proxyPoolSourceEl) {
  proxyPoolSourceEl.addEventListener("change", () => {
    applyProxyPoolSourceUI(currentProxyPoolSource());
  });
}

async function syncEmbeddedNodesToPool(opts) {
  const healthyOnly = !!(opts && opts.healthyOnly);
  try {
    setMsg(healthyOnly ? "正在导出健康节点到代理池…" : "正在导出节点到代理池…");
    const saved = await api("/api/config-center", {
      method: "PUT",
      body: JSON.stringify(buildConfigCenterPayload()),
    });
    fill(saved);
    const data = await api("/api/embedded-proxy/export-to-pool", {
      method: "POST",
      body: JSON.stringify({
        healthy_only: healthyOnly,
        switch_to_manual: true,
        set_proxy_mode: "pool",
        keep_embedded_enabled: true,
      }),
    });
    if (data && data.proxy_pool) {
      if ($("proxyPoolText")) $("proxyPoolText").value = data.proxy_pool.text || "";
      if ($("proxyPoolTextPreview")) $("proxyPoolTextPreview").value = data.proxy_pool.text || "";
      if ($("poolMeta")) {
        $("poolMeta").textContent = `代理池文件: ${data.proxy_pool.path || "-"} | 有效行: ${data.proxy_pool.line_count || 0} | 存在: ${data.proxy_pool.exists ? "是" : "否"}`;
      }
    }
    await loadAll();
    const n = (data && data.exported_count) || 0;
    const mode = (data && data.proxy_mode) || "pool";
    setMsg(`已写入代理池 ${n} 条本地口 | 来源=手动 | 代理模式=${mode} | 节点池保持开启（可混合）`);
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
}

if ($("btnSyncHealthyToPool")) {
  $("btnSyncHealthyToPool").onclick = () => syncEmbeddedNodesToPool({ healthyOnly: true });
}
if ($("btnSyncAllToPool")) {
  $("btnSyncAllToPool").onclick = () => syncEmbeddedNodesToPool({ healthyOnly: false });
}
if ($("btnImportCleanEmbedded")) {
  $("btnImportCleanEmbedded").onclick = async () => {
    try {
      setMsg("正在读取 clean 本地口…");
      const data = await api("/api/proxy-pool/import-clean-embedded", {
        method: "POST",
        body: JSON.stringify({ write_pool: false }),
      });
      const text = (data && data.text) || "";
      if ($("proxyPoolText")) $("proxyPoolText").value = text;
      const src = fieldEl("proxy_pool_source");
      if (src) src.value = "manual";
      applyProxyPoolSourceUI("manual");
      setMsg(`已导入 clean 列表 ${(data && data.line_count) || 0} 条到编辑框（尚未保存，可点「保存代理池」）`);
    } catch (e) {
      setMsg(String(e.message || e), true);
    }
  };
}

function setCpaMsg(text, isError=false) {
  const el = $("cpaPushMsg");
  if (!el) return;
  el.textContent = text || "";
  el.className = "msg" + (isError ? " err" : "");
}

function renderCpaResult(data) {
  const box = $("cpaPushResult");
  if (!box) return;
  if (!data) {
    box.textContent = "等待操作…";
    return;
  }
  const lines = [];
  if (data.message) lines.push(String(data.message));
  if (data.base_url) lines.push(`接口: ${data.base_url}`);
  if (data.api_key_masked) lines.push(`密钥: ${data.api_key_masked}`);
  if (data.total != null) lines.push(`远端总数: ${data.total} | 活跃: ${data.active ?? "-"} | 停用: ${data.disabled ?? "-"}`);
  if (data.providers && typeof data.providers === "object") {
    const parts = Object.entries(data.providers).map(([k, v]) => `${k}=${v}`);
    if (parts.length) lines.push(`Provider: ${parts.join(", ")}`);
  }
  if (data.success != null || data.failed != null) {
    lines.push(`推送: 成功 ${data.success || 0} / 失败 ${data.failed || 0} / 跳过 ${data.skipped || 0} / 共 ${data.total || 0}`);
  }
  if (data.output_dir) lines.push(`本地目录: ${data.output_dir}`);
  if (Array.isArray(data.logs) && data.logs.length) {
    lines.push("");
    lines.push("日志:");
    data.logs.slice(0, 40).forEach((l) => lines.push(`- ${l}`));
    if (data.logs.length > 40) lines.push(`… 还有 ${data.logs.length - 40} 行`);
  }
  if (Array.isArray(data.items) && data.items.length) {
    lines.push("");
    lines.push("明细:");
    data.items.slice(0, 20).forEach((it) => {
      const r = it.result || {};
      const st = r.ok ? "OK" : "FAIL";
      lines.push(`[${st}] ${it.email || "-"} -> ${r.target_name || "-"} | ${r.message || ""}`);
    });
    if (data.items.length > 20) lines.push(`… 还有 ${data.items.length - 20} 条`);
  }
  box.textContent = lines.join("\n") || JSON.stringify(data, null, 2);
}

function collectCpaOverride() {
  const g = (name, isCheck=false) => {
    const el = fieldEl(name);
    if (!el) return isCheck ? false : "";
    return isCheck ? !!el.checked : (el.value || "");
  };
  return {
    cpa_api_url: g("cpa_api_url"),
    cpa_api_key: g("cpa_api_key"),
    cpa_use_local_name: g("cpa_use_local_name", true),
    cpa_skip_duplicates: g("cpa_skip_duplicates", true),
  };
}

const btnCpaTest = $("btnCpaTest");
if (btnCpaTest) {
  btnCpaTest.onclick = async () => {
    try {
      btnCpaTest.disabled = true;
      setCpaMsg("正在测试 CPA 连接…");
      const data = await api("/api/cpa-push/test", {
        method: "POST",
        body: JSON.stringify(collectCpaOverride()),
      });
      renderCpaResult(data);
      setCpaMsg(data.message || "连接成功");
    } catch (e) {
      setCpaMsg(String(e.message || e), true);
      renderCpaResult({ message: String(e.message || e) });
    } finally {
      btnCpaTest.disabled = false;
    }
  };
}

const btnCpaPush = $("btnCpaPush");
if (btnCpaPush) {
  btnCpaPush.onclick = async () => {
    if (!window.confirm("将把本地 OAuth 输出目录中的凭证推送到 CPA，确认继续？")) return;
    try {
      btnCpaPush.disabled = true;
      setCpaMsg("正在推送本地凭证…");
      const data = await api("/api/cpa-push/upload", {
        method: "POST",
        body: JSON.stringify(collectCpaOverride()),
      });
      renderCpaResult(data);
      setCpaMsg(data.message || "推送完成", !!data.has_errors);
    } catch (e) {
      setCpaMsg(String(e.message || e), true);
      renderCpaResult({ message: String(e.message || e) });
    } finally {
      btnCpaPush.disabled = false;
    }
  };
}

const btnCpaSaveHint = $("btnCpaSaveHint");
if (btnCpaSaveHint) {
  btnCpaSaveHint.onclick = () => {
    const save = $("btnSaveCfg");
    if (save) save.click();
    else setCpaMsg("请使用顶部「保存配置」写入 CPA 设置");
  };
}
