const $ = (id) => document.getElementById(id);
const msg = $("credMsg");

function setMsg(text, isError=false) {
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

const CRED_PAGE_SIZE = 1000;
let credPage = 1;
let credTotalPages = 1;

function formatBytes(n) {
  const num = Number(n || 0);
  if (num < 1024) return `${num} B`;
  if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
  return `${(num / (1024 * 1024)).toFixed(2)} MB`;
}

function formatTime(ts) {
  const t = Number(ts || 0) * 1000;
  if (!t) return "-";
  try {
    return new Date(t).toLocaleString();
  } catch {
    return "-";
  }
}

function renderCredentials(data) {
  const total = Number(data.total || 0);
  const page = Number(data.page || 1);
  const totalPages = Number(data.total_pages || 1);
  const pageSize = Number(data.page_size || CRED_PAGE_SIZE);
  credPage = page;
  credTotalPages = totalPages;
  $("credPath").textContent = `目录: ${data.output_dir || "-"} | 存在: ${data.exists ? "是" : "否"}`;
  $("credMeta").textContent = `共 ${total} 条 · 每页 ${pageSize} · 明文 json____sso`;
  $("credListText").value = data.text || "";
  $("credPageInfo").textContent = `第 ${page} / ${totalPages} 页`;
  $("credPageInput").value = String(page);
  $("credPageInput").max = String(totalPages);
  $("btnCredPrev").disabled = page <= 1;
  $("btnCredNext").disabled = page >= totalPages;
}

async function loadCredentials(page = credPage) {
  const target = Math.max(1, Number(page || 1));
  const data = await api(`/api/credentials?page=${target}&page_size=${CRED_PAGE_SIZE}`);
  renderCredentials(data || {});
  return data;
}

let activeExportName = "";

function setExportPreview(text, meta) {
  $("exportPreviewText").value = text || "";
  $("exportPreviewMeta").textContent = meta || "点击“查看”打开 exports 中的历史 txt";
}

function markActiveExportRow(name) {
  activeExportName = name || "";
  const body = $("exportTableBody");
  body.querySelectorAll("tr[data-name]").forEach((tr) => {
    tr.classList.toggle("is-active", tr.getAttribute("data-name") === activeExportName);
  });
}

async function previewExport(name) {
  // 拉满原始 json____sso 全文（后端上限 2MB，覆盖每页最多 1000 条导出）
  const data = await api(
    `/api/credential-exports/preview?name=${encodeURIComponent(name)}&max_chars=2000000`
  );
  const lines = Number(data.line_count || 0);
  const size = formatBytes(data.size);
  const text = String(data.text || "");
  const shownLines = text ? text.split("\n").filter((l, i, arr) => l || i < arr.length - 1).length : 0;
  const trunc = data.truncated
    ? ` · 内容过长已截断预览（已显示约 ${shownLines}/${lines} 行，请点下载看全文）`
    : ` · 完整原文 ${shownLines} 行`;
  setExportPreview(
    text,
    `正在查看: ${data.name || name} · ${lines} 行 · ${size}${trunc}`
  );
  markActiveExportRow(String(data.name || name));
  return data;
}

function renderExports(data) {
  const items = data.items || [];
  $("exportPath").textContent = `目录: ${data.export_dir || "-"} | 存在: ${data.exists ? "是" : "否"}`;
  $("exportMeta").textContent = `共 ${data.total || 0} 个历史 txt · 可查看 / 下载 / 删除`;
  const body = $("exportTableBody");
  if (!items.length) {
    body.innerHTML = `<tr><td colspan="5" class="muted">暂无历史导出文件</td></tr>`;
    if (activeExportName) {
      setExportPreview("", "历史文件已空");
      activeExportName = "";
    }
    return;
  }
  body.innerHTML = items.map((item) => {
    const name = String(item.name || "");
    const safeName = encodeURIComponent(name);
    const escaped = name.replace(/"/g, "&quot;");
    return `
      <tr data-name="${escaped}">
        <td><code>${name}</code></td>
        <td>${Number(item.line_count || 0)}</td>
        <td>${formatBytes(item.size)}</td>
        <td>${formatTime(item.mtime)}</td>
        <td>
          <div class="export-actions">
            <button type="button" class="btn-export-view" data-name="${escaped}">查看</button>
            <a class="btn" href="/api/credential-exports/download?name=${safeName}">下载</a>
            <button type="button" class="btn-export-delete" data-name="${escaped}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  body.querySelectorAll(".btn-export-view").forEach((btn) => {
    btn.onclick = async () => {
      const name = btn.getAttribute("data-name") || "";
      if (!name) return;
      try {
        btn.disabled = true;
        await previewExport(name);
        setMsg(`已打开历史文件: ${name}`);
      } catch (e) {
        setMsg(String(e.message || e), true);
      } finally {
        btn.disabled = false;
      }
    };
  });

  body.querySelectorAll(".btn-export-delete").forEach((btn) => {
    btn.onclick = async () => {
      const name = btn.getAttribute("data-name") || "";
      if (!name) return;
      if (!window.confirm(`确认删除历史导出文件？\n${name}`)) return;
      try {
        btn.disabled = true;
        await api(`/api/credential-exports?name=${encodeURIComponent(name)}`, { method: "DELETE" });
        if (activeExportName === name) {
          setExportPreview("", "已删除当前预览文件");
          activeExportName = "";
        }
        setMsg(`已删除导出文件: ${name}`);
        await loadExports();
      } catch (e) {
        setMsg(String(e.message || e), true);
      } finally {
        btn.disabled = false;
      }
    };
  });

  markActiveExportRow(activeExportName);
}

async function loadExports() {
  const data = await api("/api/credential-exports");
  renderExports(data || {});
  return data;
}

$("btnCredRefresh").onclick = async () => {
  try {
    await loadCredentials(credPage);
    setMsg(`已刷新（第 ${credPage} 页）`);
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
};

$("btnCredPrev").onclick = async () => {
  if (credPage <= 1) return;
  try {
    await loadCredentials(credPage - 1);
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
};

$("btnCredNext").onclick = async () => {
  if (credPage >= credTotalPages) return;
  try {
    await loadCredentials(credPage + 1);
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
};

$("btnCredGoto").onclick = async () => {
  try {
    const page = Number($("credPageInput").value || 1);
    await loadCredentials(page);
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
};

$("btnCredCopyPage").onclick = async () => {
  try {
    const text = $("credListText").value || "";
    if (!text.trim()) {
      setMsg("当前页没有可复制内容", true);
      return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      $("credListText").focus();
      $("credListText").select();
      document.execCommand("copy");
    }
    setMsg("本页凭证已复制到剪贴板");
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
};

$("btnCredExportPage").onclick = async () => {
  try {
    const text = $("credListText").value || "";
    if (!text.trim()) {
      setMsg("当前页没有可导出内容", true);
      return;
    }
    const ok = window.confirm(
      `确认导出第 ${credPage} 页？\n` +
      `1) 写入 exports/grok+时间戳.txt\n` +
      `2) 校验成功后删除本页对应本地 .json/.sso\n` +
      `此操作不可恢复。`
    );
    if (!ok) {
      setMsg("已取消导出");
      return;
    }
    $("btnCredExportPage").disabled = true;
    setMsg("正在导出并删除本地凭证…");
    const data = await api("/api/credentials/export-page", {
      method: "POST",
      body: JSON.stringify({ page: credPage, page_size: CRED_PAGE_SIZE }),
    });
    const deleted = Number(data.deleted_count || 0);
    const exported = Number(data.exported_count || 0);
    const errs = data.delete_errors || [];
    let message = `已导出 ${exported} 条到 ${data.filename || "-"}（${data.export_dir || "exports"}）；已删除本地文件 ${deleted} 个`;
    if (errs.length) {
      message += `；删除失败 ${errs.length} 个`;
      setMsg(message, true);
    } else {
      setMsg(message);
    }
    await Promise.all([loadCredentials(credPage), loadExports()]);
  } catch (e) {
    setMsg(String(e.message || e), true);
  } finally {
    $("btnCredExportPage").disabled = false;
  }
};

$("btnExportRefresh").onclick = async () => {
  try {
    await loadExports();
    setMsg("导出列表已刷新");
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
};

$("btnExportPreviewCopy").onclick = async () => {
  try {
    const text = $("exportPreviewText").value || "";
    if (!text.trim()) {
      setMsg("预览区为空", true);
      return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      $("exportPreviewText").focus();
      $("exportPreviewText").select();
      document.execCommand("copy");
    }
    setMsg("历史文件预览已复制");
  } catch (e) {
    setMsg(String(e.message || e), true);
  }
};

$("btnExportPreviewClear").onclick = () => {
  setExportPreview("", "点击“查看”打开 exports 中的历史 txt");
  markActiveExportRow("");
  setMsg("已清空预览");
};

Promise.all([loadCredentials(1), loadExports()]).catch((e) => setMsg(String(e.message || e), true));

