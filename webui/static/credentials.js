const $ = (id) => document.getElementById(id);

const state = {
  page: 1,
  pageSize: 1000,
  totalPages: 1,
  total: 0,
  previewName: "",
  previewText: "",
  exports: [],
};

function setMessage(id, text, isError = false) {
  const el = $(id);
  if (!el) return;
  el.textContent = text || "";
  el.style.color = isError ? "#ff6b6b" : "#f0b429";
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const raw = await response.text();
  let body = null;
  try {
    body = raw ? JSON.parse(raw) : null;
  } catch {
    body = { detail: raw };
  }
  if (!response.ok) {
    const detail = body && body.detail ? body.detail : response.statusText;
    throw new Error(String(detail || `HTTP ${response.status}`));
  }
  return body || {};
}

function formatBytes(value) {
  let size = Number(value || 0);
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function formatTime(epochSeconds) {
  const value = Number(epochSeconds || 0);
  if (!Number.isFinite(value) || value <= 0) return "-";
  return new Date(value * 1000).toLocaleString();
}

async function copyText(text) {
  const value = String(text || "");
  if (!value) throw new Error("没有可复制的内容");
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const helper = document.createElement("textarea");
  helper.value = value;
  helper.setAttribute("readonly", "");
  helper.style.position = "fixed";
  helper.style.opacity = "0";
  document.body.appendChild(helper);
  helper.select();
  const copied = document.execCommand("copy");
  helper.remove();
  if (!copied) throw new Error("复制操作未完成");
}

function updateCredentialPager() {
  $("btnCredPrev").disabled = state.page <= 1;
  $("btnCredNext").disabled = state.page >= state.totalPages;
  $("credPageInput").value = String(state.page);
  $("credPageInput").max = String(Math.max(1, state.totalPages));
  $("credPageSize").value = String(state.pageSize);
}

async function loadCredentials(requestedPage = state.page) {
  setMessage("credMsg", "正在刷新…");
  const params = new URLSearchParams({
    page: String(Math.max(1, Number(requestedPage) || 1)),
    page_size: String(state.pageSize),
  });
  try {
    const data = await api(`/api/credentials?${params.toString()}`);
    state.page = Number(data.page || 1);
    state.pageSize = Number(data.page_size || state.pageSize || 1000);
    state.totalPages = Math.max(1, Number(data.total_pages || 1));
    state.total = Math.max(0, Number(data.total || 0));
    $("credListText").value = String(data.text || "");
    $("credMeta").textContent =
      `共 ${state.total} 条 · 第 ${state.page}/${state.totalPages} 页 · ` +
      `每页 ${state.pageSize} 条 · ${data.output_dir || "-"}`;
    updateCredentialPager();
    setMessage("credMsg", state.total ? "已刷新" : "当前目录暂无凭证");
    return data;
  } catch (error) {
    $("credListText").value = "";
    $("credMeta").textContent = "读取出错";
    setMessage("credMsg", String(error.message || error), true);
    throw error;
  }
}

function actionButton(label, handler, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (className) button.className = className;
  button.addEventListener("click", handler);
  return button;
}

function renderExports() {
  const body = $("exportTableBody");
  body.replaceChildren();

  if (!state.exports.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "muted";
    cell.textContent = "暂无历史导出";
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  for (const item of state.exports) {
    const name = String(item.name || "");
    const row = document.createElement("tr");
    row.dataset.exportName = name;
    if (name && name === state.previewName) row.classList.add("is-active");

    const nameCell = document.createElement("td");
    nameCell.textContent = name || "-";
    nameCell.title = String(item.path || name);

    const linesCell = document.createElement("td");
    linesCell.textContent = String(item.line_count == null ? "-" : item.line_count);

    const sizeCell = document.createElement("td");
    sizeCell.textContent = formatBytes(item.size);

    const timeCell = document.createElement("td");
    timeCell.textContent = formatTime(item.mtime);

    const actionsCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "export-actions";
    actions.appendChild(actionButton("预览", () => previewExport(name)));

    const download = document.createElement("a");
    download.textContent = "下载";
    download.href = `/api/credential-exports/download?name=${encodeURIComponent(name)}`;
    download.download = name;
    actions.appendChild(download);
    actions.appendChild(actionButton("删除", () => deleteExport(name)));
    actionsCell.appendChild(actions);

    row.append(nameCell, linesCell, sizeCell, timeCell, actionsCell);
    body.appendChild(row);
  }
}

async function loadExports() {
  setMessage("exportMsg", "正在刷新…");
  try {
    const data = await api("/api/credential-exports");
    state.exports = Array.isArray(data.items) ? data.items : [];
    $("exportMeta").textContent =
      `共 ${Number(data.total || state.exports.length)} 个文件 · ${data.export_dir || "-"}`;
    renderExports();
    setMessage("exportMsg", "已刷新");
    return data;
  } catch (error) {
    state.exports = [];
    renderExports();
    $("exportMeta").textContent = "读取出错";
    setMessage("exportMsg", String(error.message || error), true);
    throw error;
  }
}

function clearPreview() {
  state.previewName = "";
  state.previewText = "";
  $("exportPreviewText").value = "";
  $("exportPreviewMeta").textContent = "选择一个历史文件查看";
  $("btnExportPreviewCopy").disabled = true;
  const download = $("btnExportPreviewDownload");
  download.href = "#";
  download.removeAttribute("download");
  download.setAttribute("aria-disabled", "true");
  renderExports();
}

async function previewExport(name) {
  if (!name) return;
  setMessage("exportMsg", `正在读取 ${name}…`);
  try {
    const params = new URLSearchParams({ name });
    const data = await api(`/api/credential-exports/preview?${params.toString()}`);
    state.previewName = String(data.name || name);
    state.previewText = String(data.text || "");
    $("exportPreviewText").value = state.previewText;
    $("exportPreviewMeta").textContent =
      `${state.previewName} · ${Number(data.line_count || 0)} 行 · ${formatBytes(data.size)}` +
      (data.truncated ? " · 预览已截断，下载可查看完整内容" : "");
    $("btnExportPreviewCopy").disabled = !state.previewText;
    const download = $("btnExportPreviewDownload");
    download.href = `/api/credential-exports/download?name=${encodeURIComponent(state.previewName)}`;
    download.download = state.previewName;
    download.setAttribute("aria-disabled", "false");
    renderExports();
    setMessage("exportMsg", "预览已加载");
  } catch (error) {
    setMessage("exportMsg", String(error.message || error), true);
  }
}

async function deleteExport(name) {
  if (!name) return;
  if (!window.confirm(`删除历史导出 ${name}？`)) return;
  setMessage("exportMsg", `正在删除 ${name}…`);
  try {
    const params = new URLSearchParams({ name });
    await api(`/api/credential-exports?${params.toString()}`, { method: "DELETE" });
    if (state.previewName === name) clearPreview();
    await loadExports();
    setMessage("exportMsg", `已删除 ${name}`);
  } catch (error) {
    setMessage("exportMsg", String(error.message || error), true);
  }
}

$("btnCredRefresh").addEventListener("click", () => {
  loadCredentials().catch(() => {});
});

$("btnCredPrev").addEventListener("click", () => {
  loadCredentials(Math.max(1, state.page - 1)).catch(() => {});
});

$("btnCredNext").addEventListener("click", () => {
  loadCredentials(Math.min(state.totalPages, state.page + 1)).catch(() => {});
});

$("btnCredGo").addEventListener("click", () => {
  loadCredentials(Number($("credPageInput").value || 1)).catch(() => {});
});

$("credPageInput").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    $("btnCredGo").click();
  }
});

$("credPageSize").addEventListener("change", () => {
  state.pageSize = Math.max(1, Math.min(1000, Number($("credPageSize").value || 1000)));
  loadCredentials(1).catch(() => {});
});

$("btnCredCopy").addEventListener("click", async () => {
  try {
    await copyText($("credListText").value);
    setMessage("credMsg", "当前页已复制");
  } catch (error) {
    setMessage("credMsg", String(error.message || error), true);
  }
});

$("btnCredExportPage").addEventListener("click", async () => {
  if (!$("credListText").value.trim()) {
    setMessage("credMsg", "当前页暂无凭证", true);
    return;
  }
  if (!window.confirm("导出当前页并在校验成功后清理对应的本地凭证文件？")) return;
  const button = $("btnCredExportPage");
  button.disabled = true;
  setMessage("credMsg", "正在导出并校验…");
  try {
    const data = await api("/api/credentials/export-page", {
      method: "POST",
      body: JSON.stringify({ page: state.page, page_size: state.pageSize }),
    });
    await Promise.all([loadCredentials(state.page), loadExports()]);
    setMessage(
      "credMsg",
      `已导出 ${Number(data.exported_count || 0)} 条到 ${data.filename || "历史文件"}` +
      `，已清理 ${Number(data.deleted_count || 0)} 个源文件`
    );
  } catch (error) {
    setMessage("credMsg", String(error.message || error), true);
  } finally {
    button.disabled = false;
  }
});

$("btnExportRefresh").addEventListener("click", () => {
  loadExports().catch(() => {});
});

$("btnExportPreviewCopy").addEventListener("click", async () => {
  try {
    await copyText(state.previewText);
    setMessage("exportMsg", "预览内容已复制");
  } catch (error) {
    setMessage("exportMsg", String(error.message || error), true);
  }
});

$("btnExportPreviewDownload").addEventListener("click", (event) => {
  if (!state.previewName) event.preventDefault();
});

Promise.allSettled([loadCredentials(1), loadExports()]);
