const $ = (id) => document.getElementById(id);
const form = $("cfgCenterForm");
const msg = $("cfgMsg");

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
    const el = form.elements.namedItem(name) || document.getElementsByName(name)[0];
    if (!el) return;
    if (isCheck) el.checked = !!value;
    else el.value = value == null ? "" : value;
  };
  set("email_provider", f.email_provider || "yyds");
  set("yyds_api_base", f.yyds_api_base || "");
  set("yyds_api_key", f.yyds_api_key || "");
  set("yyds_jwt", f.yyds_jwt || "");
  set("turnstile_provider", f.turnstile_provider || "local");
  set("turnstile_api_key", f.turnstile_api_key || "");
  set("turnstile_headless", !!f.turnstile_headless, true);
  set(
    "local_turnstile_max_workers",
    f.local_turnstile_max_workers == null ? 3 : f.local_turnstile_max_workers
  );
  set("cloudflare_api_base", f.cloudflare_api_base || "");
  set("cloudflare_api_key", f.cloudflare_api_key || "");
  set("duckmail_api_key", f.duckmail_api_key || "");
  set("ms_mail_file", f.ms_mail_file || "");
  set("proxy_mode", f.proxy_mode || "auto");
  set("proxy", f.proxy || "");
  set("proxy_file", f.proxy_file || "proxies.txt");
  set("proxy_parent", f.proxy_parent || "");
  set("local_proxy_port", f.local_proxy_port || 17890);
  set("proxy_random", !!f.proxy_random, true);
  set("proxy_rotate_session", !!f.proxy_rotate_session, true);
  set("xai_oauth_output_dir", f.xai_oauth_output_dir || "");
  set("grok2api_remote_base", f.grok2api_remote_base || "");
  set("grok2api_remote_app_key", f.grok2api_remote_app_key || "");
  set("grok2api_pool_name", f.grok2api_pool_name || "");

  ["yyds_api_key","yyds_jwt","turnstile_api_key","cloudflare_api_key","duckmail_api_key","grok2api_remote_app_key"]
    .forEach(k => setFlag(k, !!flags[k] || !!(f[k] && String(f[k]).trim())));

  const pool = data.proxy_pool || {};
  $("proxyPoolText").value = pool.text || "";
  $("poolMeta").textContent = `代理池文件: ${pool.path || "-"} | 有效行: ${pool.line_count || 0} | 存在: ${pool.exists ? "是" : "否"}`;
}

function collectFields() {
  const g = (name, isCheck=false) => {
    const el = form.elements.namedItem(name) || document.getElementsByName(name)[0];
    if (!el) return undefined;
    if (isCheck) return !!el.checked;
    return el.value;
  };
  return {
    email_provider: g("email_provider"),
    yyds_api_base: g("yyds_api_base"),
    yyds_api_key: g("yyds_api_key"),
    yyds_jwt: g("yyds_jwt"),
    turnstile_provider: g("turnstile_provider"),
    turnstile_api_key: g("turnstile_api_key"),
    turnstile_headless: g("turnstile_headless", true),
    local_turnstile_max_workers: Number(g("local_turnstile_max_workers") || 3),
    cloudflare_api_base: g("cloudflare_api_base"),
    cloudflare_api_key: g("cloudflare_api_key"),
    duckmail_api_key: g("duckmail_api_key"),
    ms_mail_file: g("ms_mail_file"),
    proxy_mode: g("proxy_mode"),
    proxy: g("proxy"),
    proxy_file: g("proxy_file"),
    proxy_parent: g("proxy_parent"),
    local_proxy_port: Number(g("local_proxy_port") || 17890),
    proxy_random: g("proxy_random", true),
    proxy_rotate_session: g("proxy_rotate_session", true),
    xai_oauth_output_dir: g("xai_oauth_output_dir"),
    grok2api_remote_base: g("grok2api_remote_base"),
    grok2api_remote_app_key: g("grok2api_remote_app_key"),
    grok2api_pool_name: g("grok2api_pool_name"),
  };
}

async function loadAll() {
  const data = await api("/api/config-center");
  fill(data);
}

$("btnReloadCfg").onclick = async () => {
  try {
    await api("/api/settings/reload", { method: "POST", body: "{}" });
    await loadAll();
    setMsg("已重载");
  } catch (e) { setMsg(String(e.message || e), true); }
};

$("btnSaveCfg").onclick = async () => {
  try {
    const payload = {
      fields: collectFields(),
      proxy_pool_text: $("proxyPoolText").value,
    };
    const data = await api("/api/config-center", { method: "PUT", body: JSON.stringify(payload) });
    fill(data);
    setMsg("配置已保存（含代理池）");
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

loadAll().catch(e => setMsg(String(e.message || e), true));


function renderProxyTest(data) {
  const lines = [];
  lines.push(`探测: ${data.probe_url || "-"} | 超时: ${data.timeout_sec || "-"}s`);
  lines.push(`来源: ${data.source || "-"} ${data.source_path || ""}`.trim());
  lines.push(`池内可用: ${data.total_available || 0} | 本次测试: ${data.tested || 0} | 成功: ${data.ok || 0} | 失败: ${data.fail || 0}`);
  lines.push("");
  (data.results || []).forEach((item) => {
    const status = item.ok ? "OK" : "FAIL";
    const latency = item.latency_ms == null ? "-" : `${item.latency_ms}ms`;
    const ip = item.exit_ip || "-";
    const err = item.error ? ` | ${item.error}` : "";
    lines.push(`[${status}] #${item.index} ${item.display || item.proxy || "-"} | ${latency} | ip=${ip}${err}`);
  });
  if (!(data.results || []).length) {
    lines.push("没有可测试的代理行（可能都是注释或为空）。");
  }
  $("proxyTestResult").textContent = lines.join("\n");
}

$("btnTestPool").onclick = async () => {
  try {
    setMsg("正在随机测试代理池…");
    $("proxyTestResult").textContent = "测试中…";
    $("btnTestPool").disabled = true;
    const data = await api("/api/proxy-pool/test", {
      method: "POST",
      body: JSON.stringify({
        count: 5,
        timeout: 12,
        text: $("proxyPoolText").value,
      }),
    });
    renderProxyTest(data);
    setMsg(`代理测试完成：成功 ${data.ok || 0} / ${data.tested || 0}`);
  } catch (e) {
    setMsg(String(e.message || e), true);
    $("proxyTestResult").textContent = "测试失败: " + String(e.message || e);
  } finally {
    $("btnTestPool").disabled = false;
  }
};


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

setupHelpTips();

