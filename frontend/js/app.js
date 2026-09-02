/* REVLab 前端逻辑 */
const $ = (sel) => document.querySelector(sel);
const workspaceNotice = $('#workspace-notice');
function setNotice(message = '', kind = 'info') {
  if (!workspaceNotice) return;
  workspaceNotice.textContent = message;
  workspaceNotice.className = `workspace-notice ${message ? `is-${kind}` : ''}`;
}
function setBusy(button, busy, label = '处理中…') {
  if (!button) return;
  if (busy) {
    button.dataset.idleLabel = button.textContent;
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    button.textContent = label;
  } else {
    button.disabled = false;
    button.removeAttribute('aria-busy');
    if (button.dataset.idleLabel) button.textContent = button.dataset.idleLabel;
  }
}
async function request(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data.detail || data || {};
    const message = typeof detail === 'string' ? detail : (detail.message || detail.error || `HTTP ${response.status}`);
    const error = new Error(message);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}
async function aiRequest(url, options = {}) {
  return request(url, options);
}
const api = {
  list: () => request('/api/samples'),
  get: (id) => request(`/api/samples/${id}`),
  pipeline: (id) => request(`/api/samples/${id}/pipeline`),
  upload: (file) => {
    const fd = new FormData();
    fd.append('file', file);
    return request('/api/samples/upload', { method: 'POST', body: fd });
  },
  analyze: (id, wf = 'full-auto', sync = false, confirmLocal = false) =>
    request(`/api/samples/${id}/analyze?workflow=${encodeURIComponent(wf)}&sync=${sync}&confirm_local_execution=${confirmLocal}`,
          { method: 'POST' }),
  disasm: (id, addr, n) =>
    request(`/api/samples/${id}/disassembly?addr=${encodeURIComponent(addr)}&max_insns=${n}`),
  status: () => request('/api/status'),
  wfList: () => request('/api/workflows'),
  wfMeta: () => request('/api/workflows/meta'),
  wfCreate: (d) => request('/api/workflows', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }),
  wfSave: (name, d) => request(`/api/workflows/${name}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }),
  wfDel: (name) => request(`/api/workflows/${name}`, { method: 'DELETE' }),
  aiGet: () => request('/api/ai/config'),
  aiSave: (d) => request('/api/ai/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }),
  aiTest: (d) => request('/api/ai/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }),
  aiChat: (msgs) => request('/api/ai/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ messages: msgs }) }),
  aiSummarize: (id, prompt) => request(`/api/ai/summarize/${id}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ prompt }) }),
  aiSessions: () => aiRequest('/api/ai/sessions'),
  aiSession: (id) => aiRequest(`/api/ai/sessions/${encodeURIComponent(id)}`),
  aiSessionCreate: (d = {}) => aiRequest('/api/ai/sessions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }),
  aiSessionSave: (id, d) => aiRequest(`/api/ai/sessions/${encodeURIComponent(id)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }),
  aiSessionDelete: (id) => aiRequest(`/api/ai/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  aiSessionSend: (id, d) => aiRequest(`/api/ai/sessions/${encodeURIComponent(id)}/messages`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }),
  aiSessionCompress: (id, d = {}) => aiRequest(`/api/ai/sessions/${encodeURIComponent(id)}/compress`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }),
  aiWorkflowGenerate: (prompt, sampleId) => aiRequest('/api/ai/workflows/generate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ prompt, sample_id: sampleId || 0 }) }),
  aiWorkflowSave: (d) => aiRequest('/api/ai/workflows/save', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }),
  engineSpec: (e) => request(`/api/engine/${e}/spec`),
  engineAnalyze: (e, body) => request(`/api/engine/${e}/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }),
  engineList: (e) => request(`/api/engine/${e}/analyses`),
  engineGet: (e, id) => request(`/api/engine/${e}/analyses/${id}`),
  engineRerun: (e, id) => request(`/api/engine/${e}/analyses/${id}/rerun`, { method: 'POST' }),
  engineDel: (e, id) => request(`/api/engine/${e}/analyses/${id}`, { method: 'DELETE' }),
  ueVersions: () => request('/api/ue/versions'),
  ueVersion: (ver) => request(`/api/ue/version/${encodeURIComponent(ver)}`),
  ueSignatures: () => request('/api/ue/signatures'),
  environment: () => aiRequest('/api/environment'),
  prepareEnvironment: (force = false) => aiRequest('/api/environment/prepare', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ force }),
  }),
  artifactRuns: () => aiRequest('/api/artifacts'),
  graphArtifacts: (taskId) => aiRequest(`/api/artifacts/${encodeURIComponent(taskId)}`),
  engineArtifacts: (engine, analysisId) => aiRequest(`/api/artifacts/engine/${encodeURIComponent(engine)}/${encodeURIComponent(analysisId)}`),
  openGraphArtifact: (taskId, artifactId, folder = false) => aiRequest(`/api/artifacts/${encodeURIComponent(taskId)}/${folder ? 'open-folder' : 'open'}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ artifact_id: artifactId }),
  }),
  openEngineArtifact: (engine, analysisId, artifactId, folder = false) => aiRequest(`/api/artifacts/engine/${encodeURIComponent(engine)}/${encodeURIComponent(analysisId)}/${folder ? 'open-folder' : 'open'}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ artifact_id: artifactId }),
  }),
  openGraphRunFolder: (taskId) => aiRequest(`/api/artifacts/${encodeURIComponent(taskId)}/open-run-folder`, { method: 'POST' }),
  openEngineRunFolder: (engine, analysisId) => aiRequest(`/api/artifacts/engine/${encodeURIComponent(engine)}/${encodeURIComponent(analysisId)}/open-run-folder`, { method: 'POST' }),
  openOutputRoot: () => aiRequest('/api/artifacts/open-output-root', { method: 'POST' }),
};

let current = null;
let pollTimer = null;
let wfMeta = {};
let currentWfName = 'full-auto';
let aiMessages = [];
let aiSessions = [];
let currentAiSessionId = null;
let environmentSnapshot = null;
let environmentTimer = null;
let artifactRuns = [];
let selectedArtifactRun = null;
let artifactRefreshTimer = null;
let artifactRefreshInFlight = null;
let artifactRefreshQueuedOptions = null;

function badge(ok) { return ok ? '<span class="badge ok">✓</span>' : '<span class="badge bad">✗</span>'; }
function ent(score) {
  let cls = 'lo';
  if (score > 7.0) cls = 'hi'; else if (score > 6.0) cls = 'mid';
  return `<span class="ent ${cls}">${score}</span>`;
}
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

/* ---------------- 导航 ---------------- */
document.querySelectorAll('.nav-btn').forEach(b => {
  b.onclick = () => {
    document.querySelectorAll('.nav-btn').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.view').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    $('#view-' + b.dataset.view).classList.add('active');
    if (b.dataset.view === 'settings') {
      loadSettings();
      loadArtifactRuns();
    }
  };
});

/* ---------------- 系统状态 ---------------- */
function loadStatus() {
  api.status().then(s => {
    const dynamicState = s.dynamic_execution || {};
    const dynamicCaps = dynamicState.capabilities || {};
    const backends = dynamicCaps.backends || {};
    const tags = [
      ['Ghidra', s.ghidra], ['UPX', s.upx], ['PE-sieve', s.pe_sieve],
      ['本机执行', backends.local?.available], ['pktmon', true]
    ].map(([n, ok]) => `<span class="pkt">${n} ${ok ? '✓' : '✗'}</span>`).join('');
    $('#sys-status').innerHTML = `动态:${s.sandbox_mode} ${tags}`;
    const env = $('#overview-environment');
    const envMeta = $('#overview-environment-meta');
    const dynamic = $('#overview-dynamic-policy');
    const dynamicMeta = $('#overview-dynamic-meta');
    const labels = {
      local: '本机执行', blocked: '未执行'
    };
    if (env) env.textContent = s.environment_ready ? '已就绪' : '待配置';
    if (envMeta) envMeta.textContent = s.environment_ready ? '核心分析能力可用' : `缺少 ${(s.environment_missing || []).length} 项能力`;
    if (dynamic) dynamic.textContent = labels[dynamicState.mode] || '未执行';
    if (dynamicMeta) dynamicMeta.textContent = dynamicState.reason || dynamicCaps.message || '动态分析未运行';
  }).catch((error) => {
    $('#sys-status').textContent = '服务状态不可用';
    const env = $('#overview-environment');
    if (env) env.textContent = '不可用';
    setNotice(`无法读取服务状态：${error.message}`, 'error');
  });
}

/* ---------------- 样本列表 ---------------- */
async function loadList() {
  const tb = $('#sample-table tbody');
  tb.innerHTML = '<tr><td colspan="9" class="table-state">正在读取样本库…</td></tr>';
  let rows;
  try { rows = await api.list(); } catch (error) {
    tb.innerHTML = `<tr><td colspan="9" class="table-state error">样本库读取失败：${esc(error.message)}</td></tr>`;
    setNotice(`样本库读取失败：${error.message}`, 'error');
    return;
  }
  const count = $('#overview-sample-count');
  const meta = $('#overview-sample-meta');
  if (count) count.textContent = rows.length;
  if (meta) meta.textContent = rows.length ? `最近 ${Math.min(rows.length, 200)} 条记录` : '还没有上传样本';
  tb.innerHTML = '';
  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="9" class="table-state">暂无样本。上传一个 PE 文件后，分析结果会出现在这里。</td></tr>';
    return;
  }
  for (const s of rows) {
    const tr = document.createElement('tr');
    tr.className = 'clickable';
    tr.onclick = () => selectSample(s.id);
    const stCls = { analyzed: 'ok', analyzing: 'warn', error: 'bad', uploaded: 'info' }[s.status] || 'info';
    tr.innerHTML = `
      <td>${s.id}</td>
      <td><b>${esc(s.file_name)}</b></td>
      <td>${s.arch || '-'}${s.machine ? ' (' + s.machine + ')' : ''}</td>
      <td>${s.is_pe ? badge(true) : badge(false)}</td>
      <td>${s.packer_verdict ? esc(s.packer_verdict) : '-'}</td>
      <td><span class="badge ${stCls}">${esc(s.status)}</span> <small>${esc(s.stage || '')}</small></td>
      <td class="mono">${s.sha256 ? s.sha256.slice(0, 16) + '…' : ''}</td>
      <td>${(s.created_at || '').slice(0, 19).replace('T', ' ')}</td>
      <td><button onclick="event.stopPropagation();selectSample(${s.id})">查看</button></td>`;
    tb.appendChild(tr);
  }
}

/* ---------------- 详情 + 工作流可视化 ---------------- */
async function selectSample(id) {
  current = id;
  const currentEl = $('#overview-current-sample');
  const currentMeta = $('#overview-current-meta');
  if (currentEl) currentEl.textContent = `#${id}`;
  if (currentMeta) currentMeta.textContent = '正在读取样本详情';
  const ueSid = $('#ue-sample-id'); if (ueSid) ueSid.value = id;
  $('#sample-detail').classList.remove('hidden');
  if (pollTimer) clearInterval(pollTimer);
  renderDetail(id);
  renderPipeline(id);
  pollTimer = setInterval(() => {
    if (current !== id) return;
    renderDetail(id);
    renderPipeline(id);
  }, 3000);
}

async function renderPipeline(id) {
  try {
    const p = await api.pipeline(id);
    const wrap = $('#wf-flow-wrap');
    if (!p.nodes || !p.nodes.length) { wrap.classList.add('hidden'); return; }
    wrap.classList.remove('hidden');
    $('#wf-flow').innerHTML = p.nodes.map((n, i) =>
      `<div class="wf-node ${n.status || 'pending'}">` +
        `<div class="wf-icon">${ICONS[n.name] || '⚙'}</div>` +
        `<div class="wf-name">${esc(TITLES[n.name] || n.name)}</div>` +
        `<div class="wf-sub">${esc(n.status)}</div>` +
        (n.duration ? `<div class="wf-time">${n.duration}s</div>` : '') +
        (n.error ? `<div class="wf-sub" style="color:var(--red)">${esc(n.error.slice(0, 60))}</div>` : '') +
      `</div>` +
      (i < p.nodes.length - 1 ? '<div class="wf-arrow">▶</div>' : '')).join('');
    const logs = p.history || [];
    if (logs.length) {
      const lg = $('#wf-log');
      lg.classList.remove('hidden');
      lg.innerHTML = logs.map(l =>
        `[${(l.started_at || '').slice(11, 19)}] ${l.stage} ${l.success ? '✓' : '✗'} ${l.error || ''}`).join('\n');
    }
    if (p.status === 'analyzing') $('#detail-status').textContent = 'analyzing · ' + p.stage;
  } catch (e) {
    $('#wf-flow-wrap').classList.remove('hidden');
    $('#wf-flow').innerHTML = `<div class="inline-state error">流水线状态读取失败：${esc(e.message)}</div>`;
  }
}

const ICONS = { identify: '🔍', unpack: '📦', disassemble: '🔬', decompile: '🧩', dynamic: '⚡', report: '📄' };
const TITLES = { identify: '识别', unpack: '脱壳', disassemble: '反汇编', decompile: '反编译', dynamic: '动态/抓包', report: '报告' };

async function renderDetail(id) {
  let s;
  try { s = await api.get(id); } catch (error) {
    $('#detail-body').innerHTML = `<div class="inline-state error">样本详情读取失败：${esc(error.message)}</div>`;
    setNotice(`样本 #${id} 读取失败：${error.message}`, 'error');
    return;
  }
  const currentMeta = $('#overview-current-meta');
  if (currentMeta) currentMeta.textContent = `${s.file_name} · ${s.status || 'unknown'}`;
  $('#detail-name').textContent = `${s.file_name} (#${s.id})`;
  const stCls = { analyzed: 'ok', analyzing: 'warn', error: 'bad', uploaded: 'info' }[s.status] || 'info';
  $('#detail-status').className = `badge ${stCls}`;
  $('#detail-status').textContent = s.status + (s.stage ? ' · ' + s.stage : '');
  const sum = s.summary || {};
  const pe = sum.pe || {};
  const pkr = pe.packer || {};
  const sec = pe.security || {};
  const rows = [
    ['SHA256', `<code>${esc(s.sha256)}</code>`],
    ['MD5', `<code>${esc(s.md5)}</code>`],
    ['imphash', `<code>${esc(s.imphash)}</code>`],
    ['大小', `${(s.file_size / 1024).toFixed(1)} KB`],
    ['架构', `${pe.machine || '-'} / ${pe.is_64bit ? '64-bit' : '32-bit'}`],
    ['子系统', pe.subsystem || '-'],
    ['入口点', `<code>${esc(pe.entry_point)}</code>`],
    ['ImageBase', `<code>${esc(pe.image_base)}</code>`],
    ['编译时间', pe.timestamp || '-'],
    ['PDB', `<code>${esc((pe.debug || {}).pdb || '')}</code>`],
    ['壳判定', pkr.packed
      ? `<span class="badge bad">${esc(pkr.verdict)}</span> <small>confidence ${pkr.confidence}%</small>`
      : '<span class="badge ok">未加壳</span>'],
    ['安全特性', `ASLR ${badge(sec.aslr)} DEP ${badge(sec.dep)} SEH ${badge(sec.seh)} CFG ${badge(sec.cfg)}`],
  ];
  let html = '<div class="kv">' + rows.map(([k, v]) => `<b>${k}</b><span>${v}</span>`).join('') + '</div>';

  const secs = (pe.sections || []).map(sc => `
    <div class="sec">
      <div class="sec-title">${esc(sc.name)} · VA ${esc(sc.virtual_address)} · ${ent(sc.entropy)}</div>
      <span class="pkt">RAW ${sc.raw_size} B</span><span class="pkt">VS ${sc.virtual_size} B</span>
      ${(sc.flags || []).map(f => `<span class="pkt">${f}</span>`).join('')}
      ${sc.suspicious ? '<span class="badge warn">可疑</span>' : ''}
    </div>`).join('');
  html += `<h3>节区(${(pe.sections || []).length})</h3>${secs}`;

  const hits = (pkr.hits || []).map(h => `<div class="sec"><b>${esc(h.name)}</b> — ${esc(h.reason)}</div>`).join('');
  if (hits) html += `<h3>壳检测命中</h3>${hits}`;

  const imps = pe.imports || [];
  html += `<h3>导入表(${imps.length} DLL)</h3><table><thead><tr><th>DLL</th><th>函数数</th><th>函数</th></tr></thead><tbody>` +
    imps.map(imp => `<tr><td><b>${esc(imp.dll)}</b></td><td>${imp.functions.length}</td><td class="mono" style="font-size:12px">${esc(imp.functions.slice(0, 30).map(f => f.name || 'ord:' + f.ordinal).join(', '))}</td></tr>`).join('') +
    `</tbody></table>`;

  const strs = sum.strings || [];
  const interesting = strs.filter(x => /http|cmd|powershell|regsvr|download|upload|password|token|\.dll|\.exe|\.pdb|socket|connect|WScript|Temp|AppData|SOFTWARE/i.test(x.value));
  html += `<h3>兴趣字符串(${interesting.length}/${strs.length})</h3><pre class="mono" style="max-height:320px">` +
    interesting.slice(0, 200).map(x => `${x.offset} ${x.type === 'unicode' ? 'U' : 'A'} ${esc(x.value)}`).join('\n') + '</pre>';

  const dec = sum.decompile || {};
  html += `<h3>反编译(Ghidra)</h3><p>${dec.ok ? `已导出 ${dec.function_count} 个函数` : esc(dec.message || '未执行')}</p>`;
  const dis = sum.disassembly || {};
  html += `<h3>反汇编</h3><p>入口指令 ${dis.count || 0} 条,函数提示 ${dis.functions_hint || 0} 个</p>`;
  const net = sum.network || {};
  html += `<h3>网络</h3><p>连接 ${(net.connections || []).length},DNS ${(net.dns_queries || []).length},HTTP ${(net.http_requests || []).length},SNI ${(net.sni || []).length}</p>`;
  const dyn = sum.dynamic || {};
  const dynBlocked = dyn.execution_status === 'blocked_by_policy' || dyn.sandbox === 'blocked';
  const dynSkipped = !Object.keys(dyn).length && (sum._pipeline_status || []).some(node => node.name === 'dynamic' && node.status === 'skipped');
  html += `<h3>动态</h3><p>${dynSkipped
    ? '<span class="badge info">未纳入工作流</span> 当前运行使用静态分析工作流。'
    : dynBlocked
    ? '<span class="badge warn">未执行</span> ' + esc(dyn.message || '本机运行需要先确认。')
    : dyn.error ? '<span class="badge bad">' + esc(dyn.error) + '</span>'
    : '本机运行 ' + ((dyn.run || {}).ran_seconds || '-') + 's,新增进程 ' + (((dyn.run || {}).behavior || {}).new_processes || []).length + ' 个'}</p>`;

  if (s.error) html += `<p class="badge bad">${esc(s.error)}</p>`;
  $('#detail-body').innerHTML = html;
}

/* ---------------- 动作 ---------------- */
$('#file-input').onchange = async (e) => {
  const files = [...e.target.files];
  if (!files.length) return;
  const progress = $('#upload-progress');
  progress.textContent = `正在上传 ${files.length} 个文件…`;
  setNotice(`开始上传 ${files.length} 个样本`, 'info');
  let completed = 0;
  for (const f of files) {
    try {
      const r = await api.upload(f);
      completed += 1;
      progress.textContent = `${completed}/${files.length} · ${f.name}${r.duplicate ? '（已存在）' : '（已登记）'}`;
    } catch (err) {
      progress.textContent = `${completed}/${files.length} · ${f.name} 上传失败`;
      setNotice(`${f.name} 上传失败：${err.message || err}`, 'error');
    }
  }
  e.target.value = '';
  await loadList(); loadStatus();
  if (completed === files.length) setNotice(`已处理 ${completed} 个样本`, 'success');
};

$('#btn-refresh').onclick = async () => {
  const button = $('#btn-refresh');
  setBusy(button, true, '刷新中…');
  try { await Promise.all([loadList(), loadStatus()]); setNotice('样本库已刷新', 'success'); }
  catch (error) { setNotice(`刷新失败：${error.message}`, 'error'); }
  finally { setBusy(button, false); }
};

$('#btn-analyze').onclick = async () => {
  if (!current) return;
  const wf = $('#upload-workflow').value || 'full-auto';
  const confirmLocal = wf === 'static-only' ? false : window.confirm(
    '该工作流可能包含动态阶段。是否确认本次在当前主机运行样本？\n\n'
    + '本机执行会使用当前用户权限、文件系统和网络，超时后才会终止进程。'
  );
  if (wf !== 'static-only' && !confirmLocal) {
    setNotice('已取消：未确认本机动态执行', 'info');
    return;
  }
  const button = $('#btn-analyze');
  setBusy(button, true, '提交中…');
  setNotice(`正在提交样本 #${current} 的 ${wf} 工作流…`, 'info');
  try {
    const r = await api.analyze(current, wf, false, confirmLocal);
    setNotice(`工作流已启动：${(r.stages || []).join(' → ')}`, 'success');
    await Promise.all([renderDetail(current), renderPipeline(current), loadList()]);
  } catch (error) {
    setNotice(`分析未启动：${error.message}`, 'error');
  } finally {
    setBusy(button, false);
  }
};

$('#btn-graph-run').onclick = () => {
  if (!current) return;
  const frame = $('#workflow-frame');
  frame.src = `/wf/?embedded=1&sample_id=${encodeURIComponent(current)}`;
  document.querySelector('.nav-btn[data-view="workflows"]').click();
};

document.querySelectorAll('[data-graph-workflow]').forEach((button) => {
  button.onclick = () => {
    const choice = button.dataset.graphWorkflow;
    document.querySelectorAll('[data-graph-workflow]').forEach((b) => b.classList.toggle('active', b === button));
    const frame = $('#workflow-frame');
    const sample = current ? `&sample_id=${encodeURIComponent(current)}` : '';
    if (choice === 'new') frame.src = `/wf/?embedded=1&new=1${sample}`;
    else frame.src = `/wf/?embedded=1&workflow=${encodeURIComponent(choice)}${sample}`;
  };
});

$('#btn-disasm').onclick = async () => {
  if (!current) return;
  const button = $('#btn-disasm');
  setBusy(button, true, '读取中…');
  let s;
  try { s = await api.get(current); } catch (error) {
    setNotice(`无法读取样本：${error.message}`, 'error');
    setBusy(button, false);
    return;
  }
  $('#disasm-panel').classList.remove('hidden');
  $('#disasm-addr').value = $('#disasm-addr').value || s.entry_point || '';
  await goDisasm();
  setBusy(button, false);
};

async function goDisasm() {
  if (!current) return;
  $('#disasm-out').textContent = '加载中…';
  const n = parseInt($('#disasm-n').value || '2000', 10);
  try {
    const r = await api.disasm(current, $('#disasm-addr').value, n);
    const lines = r.insns.map(i =>
      `${i.address.toString(16).padStart(8, '0')}  ${i.bytes.padEnd(24, ' ')}  ${i.mnemonic} ${i.op_str}`);
    $('#disasm-out').textContent = lines.join('\n');
    document.querySelector('#view-sandbox').classList.add('active');
    document.querySelector('[data-view=sandbox]').classList.add('active');
    document.querySelector('[data-view=samples]').classList.remove('active');
    $('#view-samples').classList.remove('active');
    $('#disasm-panel').scrollIntoView({ behavior: 'smooth' });
  } catch (err) {
    $('#disasm-out').textContent = '错误: ' + (err.message || err);
    setNotice(`反汇编失败：${err.message || err}`, 'error');
  }
}
$('#btn-go-disasm').onclick = goDisasm;

$('#btn-report').onclick = () => {
  if (current) window.open(`/api/samples/${current}/report?fmt=html`, '_blank');
};

if ($('#btn-sample-output')) $('#btn-sample-output').onclick = () => openConfiguredOutputRoot($('#set-status'));

$('#btn-del').onclick = async () => {
  if (!current) return;
  if (!confirm('确认删除该样本及其分析记录?')) return;
  try {
    await request(`/api/samples/${current}`, { method: 'DELETE' });
  } catch (error) {
    setNotice(`删除失败：${error.message}`, 'error');
    return;
  }
  current = null;
  $('#sample-detail').classList.add('hidden');
  $('#overview-current-sample').textContent = '未选择';
  $('#overview-current-meta').textContent = '从列表选择一个样本';
  setNotice('样本已删除', 'success');
  loadList();
};

/* ---------------- 工作流编辑器 ---------------- */
async function loadWorkflowUI() {
  const wfs = await api.wfList();
  wfMeta = await api.wfMeta();
  const sel = $('#wf-select');
  const upSel = $('#upload-workflow');
  upSel.innerHTML = wfs.map(w => `<option value="${esc(w.name)}">${esc(w.name)}${w.is_default ? ' (默认)' : ''}</option>`).join('');
  if (!sel) return;
  sel.innerHTML = wfs.map(w => `<option value="${esc(w.name)}">${esc(w.name)}${w.is_default ? ' (默认)' : ''}</option>`).join('');
  sel.onchange = () => { currentWfName = sel.value; renderWorkflowEditor(); };
  renderWorkflowEditor();
}

async function renderWorkflowEditor() {
  const wfs = await api.wfList();
  const w = wfs.find(x => x.name === currentWfName) || wfs[0];
  if (!w) return;
  $('#wf-name').value = w.name;
  $('#wf-desc').value = w.description || '';
  const ed = $('#wf-editor');
  ed.innerHTML = w.stages.map((st, i) => {
    const meta = wfMeta[st.name] || { params: {}, desc: '' };
    const pms = Object.entries(meta.params || {}).map(([k, v]) => {
      const val = (st.params || {})[k];
      if (v.type === 'bool') return `<label><input type="checkbox" data-wf-param="${k}" ${val ? 'checked' : ''}>${esc(v.label)}</label>`;
      if (v.type === 'multi') return `<label>${esc(v.label)} <input type="text" data-wf-param="${k}" value="${esc((val || []).join(','))}"></label>`;
      if (v.type === 'select') return `<label>${esc(v.label)} <select data-wf-param="${k}">${(v.options || []).map(o => `<option value="${esc(o)}" ${String(o) === String(val ?? v.default) ? 'selected' : ''}>${esc({local: '本机执行'}[o] || o)}</option>`).join('')}</select></label>`;
      return `<label>${esc(v.label)} <input type="number" data-wf-param="${k}" value="${esc(val ?? v.default)}" min="${v.min}" max="${v.max}"></label>`;
    }).join('');
    return `<div class="wf-stage">
      <span class="order">${i + 1}</span>
      <label><input type="checkbox" data-wf-enabled ${st.enabled ? 'checked' : ''}></label>
      <span class="st-name">${esc(TITLES[st.name] || st.name)}</span>
      <span class="st-title">${esc(meta.desc || '')}</span>
      <span class="params">${pms}</span>
      <button data-wf-move="up" ${i === 0 ? 'disabled' : ''}>↑</button>
      <button data-wf-move="down" ${i === w.stages.length - 1 ? 'disabled' : ''}>↓</button>
    </div>`;
  }).join('');

  // 事件绑定
  ed.querySelectorAll('button[data-wf-move]').forEach(b => b.onclick = () => {
    const idx = [...ed.children].indexOf(b.closest('.wf-stage'));
    const list = [...ed.children];
    if (b.dataset.wfMove === 'up' && idx > 0) list[idx].before(list[idx - 1]);
    if (b.dataset.wfMove === 'down' && idx < list.length - 1) list[idx].after(list[idx + 1]);
  });

  // 预览
  renderWfPreview(w);
}

function collectWorkflow() {
  const name = $('#wf-name').value.trim();
  const desc = $('#wf-desc').value.trim();
  const stages = [];
  $('#wf-editor').querySelectorAll('.wf-stage').forEach(el => {
    const span = el.querySelector('.st-name');
    const name = [...Object.entries(TITLES)].find(([, t]) => t === span.textContent);
    const stName = Object.keys(TITLES).find(k => TITLES[k] === span.textContent);
    if (!stName) return;
    const params = {};
    el.querySelectorAll('[data-wf-param]').forEach(inp => {
      const meta = wfMeta[stName]?.params?.[inp.dataset.wfParam];
      if (inp.type === 'checkbox') params[inp.dataset.wfParam] = inp.checked;
      else if (meta && meta.type === 'multi') params[inp.dataset.wfParam] = inp.value.split(',').map(s => s.trim()).filter(Boolean);
      else if (inp.type === 'number') params[inp.dataset.wfParam] = parseInt(inp.value || '0', 10);
      else params[inp.dataset.wfParam] = inp.value;
    });
    stages.push({ name: stName, enabled: el.querySelector('[data-wf-enabled]').checked, params });
  });
  return { name, description: desc, stages };
}

if ($('#btn-wf-new')) $('#btn-wf-new').onclick = () => {
  const n = prompt('新工作流名称(英文/数字/中划线):', 'my-flow');
  if (!n) return;
  api.wfCreate({ name: n }).then(r => { if (r.ok) { currentWfName = n; loadWorkflowUI(); setNotice(`工作流 ${n} 已创建`, 'success'); } })
    .catch(error => setNotice(`创建工作流失败：${error.message}`, 'error'));
};

if ($('#btn-wf-save')) $('#btn-wf-save').onclick = async () => {
  const d = collectWorkflow();
  if (!d.name) { setNotice('请填写工作流名称', 'error'); return; }
  try {
    const r = await api.wfSave(d.name, d);
    if (r.ok) { $('#wf-status').textContent = '已保存'; setTimeout(() => $('#wf-status').textContent = '', 2000); loadWorkflowUI(); setNotice('工作流已保存', 'success'); }
  } catch (error) { setNotice(`保存工作流失败：${error.message}`, 'error'); }
};

if ($('#btn-wf-del')) $('#btn-wf-del').onclick = async () => {
  const w = $('#wf-select').value;
  if (!confirm(`删除工作流「${w}」?`)) return;
  try {
    const r = await api.wfDel(w);
    if (r.ok) { currentWfName = 'full-auto'; loadWorkflowUI(); setNotice('工作流已删除', 'success'); }
  } catch (error) { setNotice(`删除工作流失败：${error.message}`, 'error'); }
};

if ($('#btn-wf-toggle')) $('#btn-wf-toggle').onclick = async () => {
  const w = $('#wf-select').value;
  const wfs = await api.wfList();
  const cur = wfs.find(x => x.name === w);
  await api.wfSave(w, { enabled: !cur.enabled });
  loadWorkflowUI();
};

function renderWfPreview(w) {
  const order = w.stages;
  $('#wf-preview-flow').innerHTML = order.map((st, i) =>
    `<div class="wf-node ${st.enabled ? 'pending' : 'skipped'}">` +
      `<div class="wf-icon">${ICONS[st.name] || '⚙'}</div>` +
      `<div class="wf-name">${esc(TITLES[st.name] || st.name)}</div>` +
      (st.enabled ? '' : '<div class="wf-sub">disabled</div>') +
    `</div>` + (i < order.length - 1 ? '<div class="wf-arrow">▶</div>' : '')).join('');
}

/* ---------------- AI 模型 ---------------- */
async function loadAI() {
  try {
    const c = await api.aiGet();
    $('#ai-enabled').checked = c.enabled;
    $('#ai-base').value = c.base_url || '';
    $('#ai-key').value = c.api_key && c.api_key !== '***' ? c.api_key : '';
    $('#ai-model').value = c.model || '';
    $('#ai-temp').value = c.temperature ?? 0.2;
    $('#ai-max-tokens').value = c.max_tokens ?? 2400;
    setReasoningFromConfig(c);
    syncAiChatControls();
  } catch (e) {
    $('#ai-status').textContent = String(e.message || e);
  }
  await loadAiSessions();
}
const AI_PROVIDERS = {
  openai: { base_url: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
  deepseek: { base_url: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
  qwen: { base_url: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen-plus' },
  zhipu: { base_url: 'https://open.bigmodel.cn/api/paas/v4', model: 'glm-4-flash' },
  moonshot: { base_url: 'https://api.moonshot.cn/v1', model: 'moonshot-v1-8k' },
  siliconflow: { base_url: 'https://api.siliconflow.cn/v1', model: 'Qwen/Qwen2.5-72B-Instruct' },
  gemini: { base_url: 'https://generativelanguage.googleapis.com/v1beta/openai', model: 'gemini-2.0-flash' },
  openrouter: { base_url: 'https://openrouter.ai/api/v1', model: 'openai/gpt-4o-mini' },
  groq: { base_url: 'https://api.groq.com/openai/v1', model: 'llama-3.3-70b-versatile' },
  together: { base_url: 'https://api.together.xyz/v1', model: 'meta-llama/Llama-3.3-70B-Instruct-Turbo' },
  mistral: { base_url: 'https://api.mistral.ai/v1', model: 'mistral-small-latest' },
  perplexity: { base_url: 'https://api.perplexity.ai', model: 'sonar' },
  azure: { base_url: 'https://YOUR-RESOURCE.openai.azure.com/openai/v1', model: 'YOUR-DEPLOYMENT', fillable: true },
  anthropic: { base_url: '', model: '', proxy: true },
  ollama: { base_url: 'http://127.0.0.1:11434/v1', model: 'qwen2.5:7b' },
  lmstudio: { base_url: 'http://127.0.0.1:1234/v1', model: 'local-model' },
};
const AI_MODEL_PRESETS = {
  openai: ['gpt-4o-mini', 'gpt-4o', 'o3-mini'], deepseek: ['deepseek-chat', 'deepseek-reasoner'],
  qwen: ['qwen-plus', 'qwen-max', 'qwen-turbo'], zhipu: ['glm-4-flash', 'glm-4-plus'],
  moonshot: ['moonshot-v1-8k', 'moonshot-v1-32k'], siliconflow: ['Qwen/Qwen2.5-72B-Instruct', 'deepseek-ai/DeepSeek-R1'],
  gemini: ['gemini-2.0-flash', 'gemini-1.5-pro'], openrouter: ['openai/gpt-4o-mini', 'anthropic/claude-3.5-sonnet', 'deepseek/deepseek-r1'],
  groq: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant'], together: ['meta-llama/Llama-3.3-70B-Instruct-Turbo', 'Qwen/Qwen2.5-72B-Instruct-Turbo'],
  mistral: ['mistral-small-latest', 'mistral-large-latest'], perplexity: ['sonar', 'sonar-pro'],
  azure: ['YOUR-DEPLOYMENT'], anthropic: [], ollama: ['qwen2.5:7b', 'deepseek-r1:7b'], lmstudio: ['local-model'],
};
function fillModelOptions(provider) {
  const models = AI_MODEL_PRESETS[provider] || [];
  $('#ai-model-options').innerHTML = models.map(m => `<option value="${esc(m)}"></option>`).join('');
  const chat = $('#ai-chat-model');
  if (chat) chat.innerHTML = models.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
}
function syncAiChatControls() {
  const activeSession = currentAiSession();
  const model = activeSession?.model || $('#ai-model')?.value || '';
  const chat = $('#ai-chat-model');
  if (chat) {
    if (!chat.querySelector(`option[value="${CSS.escape(model)}"]`)) chat.insertAdjacentHTML('afterbegin', `<option value="${esc(model)}">${esc(model)}</option>`);
    chat.value = model;
  }
  const r = activeSession?.reasoning || $('#ai-reasoning')?.value || 'balanced';
  if ($('#ai-chat-reasoning')) $('#ai-chat-reasoning').value = r;
}
function setReasoningFromConfig(c) {
  const max = Number(c.max_tokens || 2400); const temp = Number(c.temperature ?? 0.2);
  $('#ai-reasoning').value = max >= 4000 || temp <= 0.1 ? 'high' : (max <= 1600 || temp >= 0.35 ? 'low' : 'balanced');
}
$('#ai-reasoning').onchange = () => {
  const values = { low: [0.35, 1400], balanced: [0.2, 2400], high: [0.08, 5000] }[$('#ai-reasoning').value];
  $('#ai-temp').value = values[0]; $('#ai-max-tokens').value = values[1];
  if (!currentAiSessionId && $('#ai-chat-reasoning')) $('#ai-chat-reasoning').value = $('#ai-reasoning').value;
};
$('#ai-chat-reasoning').onchange = () => { persistAiSessionSettings(); };
$('#ai-chat-model').onchange = () => { persistAiSessionSettings(); };
$('#ai-provider').onchange = () => {
  const preset = AI_PROVIDERS[$('#ai-provider').value];
  if (!preset) return;
  if (preset.proxy) {
    $('#ai-base').value = '';
    $('#ai-model').value = '';
    fillModelOptions($('#ai-provider').value);
    $('#ai-status').textContent = 'Anthropic 使用 Messages API；请填写 LiteLLM、OpenRouter 等 OpenAI 兼容代理地址和模型后保存。';
    return;
  }
  $('#ai-base').value = preset.base_url;
  $('#ai-model').value = preset.model;
  fillModelOptions($('#ai-provider').value);
  syncAiChatControls();
  $('#ai-status').textContent = preset.fillable
    ? '请将 Azure 资源名和部署名替换为实际值，再填写 API Key 保存。'
    : '已填充厂商默认配置，填写密钥后保存。';
};
function currentAiSession() {
  return aiSessions.find((session) => session.id === currentAiSessionId) || null;
}
function setAiChatModel(model) {
  const select = $('#ai-chat-model');
  if (!select) return;
  const value = model || $('#ai-model')?.value || '';
  if (value && !Array.from(select.options).some((option) => option.value === value)) {
    select.insertAdjacentHTML('afterbegin', `<option value="${esc(value)}">${esc(value)}</option>`);
  }
  select.value = value;
}
function renderAiSessionList() {
  const list = $('#ai-session-list');
  if (!list) return;
  if (!aiSessions.length) {
    list.innerHTML = '<div class="ai-empty">尚无对话</div>';
    return;
  }
  list.innerHTML = aiSessions.map((session) => {
    const active = session.id === currentAiSessionId ? 'active' : '';
    const detail = [session.model || '默认模型', session.reasoning || 'balanced', session.sample_id ? `样本 #${session.sample_id}` : '无样本'].join(' · ');
    return `<button class="ai-session-item ${active}" data-ai-session="${esc(session.id)}"><b>${esc(session.title || '新对话')}</b><small>${esc(detail)}</small></button>`;
  }).join('');
  list.querySelectorAll('[data-ai-session]').forEach((button) => {
    button.onclick = () => selectAiSession(button.dataset.aiSession);
  });
}
function renderAiChat() {
  const box = $('#ai-chat-log');
  if (!box) return;
  if (!currentAiSessionId) {
    box.innerHTML = '<div class="ai-empty">正在创建对话…</div>';
    return;
  }
  if (!aiMessages.length) {
    box.innerHTML = '<div class="ai-empty">这个对话会独立保存模型、思考强度和样本上下文。输入问题即可开始。</div>';
    return;
  }
  box.innerHTML = aiMessages.map((message) =>
    `<div class="ai-msg ${message.role} ${message.pending ? 'pending' : ''} ${message.error ? 'error' : ''}">${esc(message.content)}</div>`
  ).join('');
  box.scrollTop = box.scrollHeight;
}
function syncAiSessionControls(session) {
  if (!session) return;
  $('#ai-session-title').value = session.title || '';
  $('#ai-chat-sample').value = session.sample_id || '';
  setAiChatModel(session.model || $('#ai-model')?.value || '');
  $('#ai-chat-reasoning').value = session.reasoning || 'balanced';
}
async function loadAiSessions() {
  try {
    const result = await api.aiSessions();
    aiSessions = result.sessions || [];
    const preferred = aiSessions.find((session) => session.id === currentAiSessionId) || aiSessions[0];
    if (preferred) await selectAiSession(preferred.id);
    else await createAiSession();
  } catch (e) {
    $('#ai-status').textContent = `会话加载失败: ${e.message || e}`;
    renderAiSessionList(); renderAiChat();
  }
}
async function createAiSession() {
  const sampleId = Number($('#ai-chat-sample')?.value || current || 0);
  const result = await api.aiSessionCreate({
    model: $('#ai-chat-model')?.value || $('#ai-model')?.value || '',
    reasoning: $('#ai-chat-reasoning')?.value || 'balanced',
    sample_id: sampleId,
  });
  aiSessions.unshift(result.session);
  await selectAiSession(result.session.id);
}
async function selectAiSession(sessionId) {
  const result = await api.aiSession(sessionId);
  currentAiSessionId = result.session.id;
  aiMessages = result.messages || [];
  const index = aiSessions.findIndex((session) => session.id === currentAiSessionId);
  if (index >= 0) aiSessions[index] = { ...aiSessions[index], ...result.session };
  else aiSessions.unshift(result.session);
  syncAiSessionControls(result.session);
  renderAiSessionList(); renderAiChat();
}
async function persistAiSessionSettings() {
  if (!currentAiSessionId) return;
  const payload = {
    title: $('#ai-session-title').value.trim() || '新对话',
    model: $('#ai-chat-model').value.trim(),
    reasoning: $('#ai-chat-reasoning').value,
    sample_id: Number($('#ai-chat-sample').value || 0),
  };
  try {
    const result = await api.aiSessionSave(currentAiSessionId, payload);
    const index = aiSessions.findIndex((session) => session.id === currentAiSessionId);
    if (index >= 0) aiSessions[index] = { ...aiSessions[index], ...result.session };
    renderAiSessionList();
  } catch (e) {
    $('#ai-status').textContent = `会话设置保存失败: ${e.message || e}`;
  }
}
async function sendAiMessage() {
  const input = $('#ai-prompt');
  const question = input.value.trim();
  if (!question) return;
  if (!currentAiSessionId) await createAiSession();
  const payload = {
    content: question,
    model: $('#ai-chat-model').value.trim(),
    reasoning: $('#ai-chat-reasoning').value,
    sample_id: Number($('#ai-chat-sample').value || current || 0),
  };
  aiMessages.push({ role: 'user', content: question });
  aiMessages.push({ role: 'assistant', content: '思考中…', pending: true });
  input.value = ''; renderAiChat();
  try {
    const result = await api.aiSessionSend(currentAiSessionId, payload);
    aiMessages[aiMessages.length - 1] = { role: 'assistant', content: result.reply || '(模型没有返回文本)' };
    const index = aiSessions.findIndex((session) => session.id === currentAiSessionId);
    if (index >= 0) aiSessions[index] = { ...aiSessions[index], ...result.session };
    syncAiSessionControls(result.session);
    renderAiSessionList();
  } catch (e) {
    aiMessages[aiMessages.length - 1] = { role: 'assistant', content: String(e.message || e), error: true };
  }
  renderAiChat();
}
$('#btn-ai-save').onclick = async () => {
  const d = {
    enabled: $('#ai-enabled').checked,
    base_url: $('#ai-base').value.trim(),
    api_key: $('#ai-key').value.trim(),
    model: $('#ai-model').value.trim(),
    temperature: parseFloat($('#ai-temp').value || '0.2'),
    max_tokens: parseInt($('#ai-max-tokens').value || '2400', 10),
  };
  const r = await api.aiSave(d);
  $('#ai-status').textContent = r.ok ? '✓ 已保存' : '保存失败';
};
$('#btn-ai-test').onclick = async () => {
  const d = {
    base_url: $('#ai-base').value.trim(),
    api_key: $('#ai-key').value.trim(),
    model: $('#ai-model').value.trim(),
    temperature: parseFloat($('#ai-temp').value || '0.2'),
  };
  $('#ai-status').textContent = '测试中…';
  const r = await api.aiTest(d);
  $('#ai-status').textContent = r.ok ? `✓ 连接成功: ${r.reply}` : `✗ ${r.error}`;
};
$('#btn-ai-summarize').onclick = async () => {
  if (!current) { setNotice('请先在样本库选择一个样本', 'error'); return; }
  $('#ai-chat-sample').value = current;
  await persistAiSessionSettings();
  $('#ai-prompt').value = '请基于当前样本给出结构化分析、关键证据和下一步工作流建议。';
  await sendAiMessage();
};
$('#btn-ai-send').onclick = async () => {
  await sendAiMessage();
};
$('#ai-prompt').onkeydown = (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAiMessage(); } };
$('#btn-ai-session-new').onclick = async () => { await createAiSession(); };
$('#btn-ai-clear').onclick = async () => { await createAiSession(); };
$('#ai-session-title').onchange = () => { persistAiSessionSettings(); };
$('#ai-chat-sample').onchange = () => { persistAiSessionSettings(); };
$('#btn-ai-compress').onclick = async () => {
  if (!currentAiSessionId) return;
  try {
    const result = await api.aiSessionCompress(currentAiSessionId, { force: true });
    $('#ai-status').textContent = result.compressed ? '已压缩早期上下文，完整消息仍会保留。' : '当前上下文无需压缩。';
  } catch (e) { $('#ai-status').textContent = `上下文压缩失败: ${e.message || e}`; }
};
$('#btn-ai-session-delete').onclick = async () => {
  if (!currentAiSessionId || !confirm('删除当前对话及其消息记录？')) return;
  try {
    await api.aiSessionDelete(currentAiSessionId);
    aiSessions = aiSessions.filter((session) => session.id !== currentAiSessionId);
    currentAiSessionId = null; aiMessages = [];
    await loadAiSessions();
  } catch (e) { $('#ai-status').textContent = `删除对话失败: ${e.message || e}`; }
};
$('#btn-ai-workflow').onclick = async () => {
  const input = $('#ai-prompt');
  const latestUser = [...aiMessages].reverse().find((message) => message.role === 'user');
  const prompt = input.value.trim() || latestUser?.content || '生成一个可编辑的 PE 分析工作流。';
  const sampleId = Number($('#ai-chat-sample').value || current || 0);
  $('#ai-workflow-status').textContent = '正在生成并验证草稿…';
  try {
    const draft = await api.aiWorkflowGenerate(prompt, sampleId);
    const saved = await api.aiWorkflowSave({ workflow: draft.workflow, generator: draft.generator });
    const warnings = (draft.warnings || []).concat(saved.warnings || []);
    $('#ai-workflow-status').textContent = `已保存「${saved.workflow.name}」${warnings.length ? `（${warnings.length} 条提示）` : ''}`;
    const frame = $('#workflow-frame');
    const sample = sampleId ? `&sample_id=${encodeURIComponent(sampleId)}` : '';
    frame.src = `/wf/?embedded=1&workflow=${encodeURIComponent(saved.workflow.name)}${sample}`;
    document.querySelector('.nav-btn[data-view="workflows"]').click();
  } catch (e) {
    $('#ai-workflow-status').textContent = `草稿生成失败: ${e.message || e}`;
  }
};
document.querySelectorAll('[data-ai-tab]').forEach((tab) => {
  tab.onclick = () => {
    const settings = tab.dataset.aiTab === 'settings';
    document.querySelectorAll('[data-ai-tab]').forEach((x) => x.classList.toggle('active', x === tab));
    $('#ai-settings-panel').classList.toggle('hidden', !settings);
    $('#ai-chat-panel').classList.toggle('hidden', settings);
  };
});

/* ---------------- 通用引擎分析(UE / Unity) ---------------- */
const engines = {
  ue:    { id: null, timer: null, titles: {}, order: [] },
  unity: { id: null, timer: null, titles: {}, order: [] },
};

function engEl(engine, id) { return document.getElementById(`${engine}-${id}`); }
function engSet(engine, id, html) { const el = engEl(engine, id); if (el) el.innerHTML = html; }

function fmtVa(v) {
  if (v == null || v === '') return '-';
  if (typeof v === 'number') return '0x' + v.toString(16);
  return String(v);
}
function kvRow(k, v) { return `<b>${esc(k)}</b><span>${v == null || v === '' ? '-' : v}</span>`; }
function pick(o, keys, def) {
  if (o == null) return def;
  for (const k of keys) if (o[k] != null) return o[k];
  return def;
}

/* 阶段进度可视化(通用组件) */
function renderStageFlow(container, stages) {
  if (!container) return;
  if (!stages || !stages.length) { container.innerHTML = '<span class="hint">暂无可视化阶段。</span>'; return; }
  container.innerHTML = stages.map((st, i) => {
    const status = st.status || 'pending';
    return `<div class="eng-node ${status}">` +
      `<div class="eng-title">${esc(st.title || st.name || '')}</div>` +
      `<div class="eng-status">${esc(status)}</div>` +
      (st.duration != null ? `<div class="eng-time">${esc(st.duration)}s</div>` : '') +
      (st.error ? `<div class="eng-err">${esc(String(st.error).slice(0, 40))}</div>` : '') +
      `</div>` + (i < stages.length - 1 ? '<div class="eng-arrow">▶</div>' : '');
  }).join('');
}

async function loadEngineSpec(engine) {
  try {
    const spec = await api.engineSpec(engine);
    engines[engine].titles = spec.titles || {};
    engines[engine].order = spec.stages || [];
    renderStageFlow(engEl(engine, 'stage-flow'), (spec.stages || []).map(s => ({
      name: s, title: (spec.titles || {})[s] || s, status: 'pending',
    })));
  } catch (e) {
    engSet(engine, 'status', `<span class="badge bad">能力说明不可用</span> ${esc(e.message || e)}`);
  }
}

function stagesFromStatus(engine, a) {
  const cfg = engines[engine];
  const order = cfg.order || [];
  if (!order.length) return null;
  const cur = a.stage;
  const idx = order.indexOf(cur);
  const done = a.status === 'done';
  const err = a.status === 'error';
  return order.map((name, i) => {
    let status = 'pending';
    if (idx >= 0) {
      if (i < idx || (done && i <= idx)) status = 'done';
      else if (i === idx) status = err ? 'error' : (done ? 'done' : 'running');
    } else if (done) status = 'done';
    return { name, title: cfg.titles[name] || name, status };
  });
}

function updateEngineUI(engine, a) {
  const result = a.result || {};
  engEl(engine, 'result').classList.remove('hidden');
  const stages = (result._stages && result._stages.length) ? result._stages : stagesFromStatus(engine, a);
  if (stages) renderStageFlow(engEl(engine, 'stage-flow'), stages);
  const stCls = { done: 'ok', running: 'warn', error: 'bad', pending: 'info' }[a.status] || 'info';
  engSet(engine, 'status', `<span class="badge ${stCls}">${esc(a.status)}</span>` + (a.stage ? ` <small>${esc(a.stage)}</small>` : ''));
  if (a.status === 'done' || a.status === 'error') {
    const body = (engine === 'ue' ? renderUEResult(result) : renderUnityResult(result)) +
      `<div id="${engine}-artifact-summary" class="engine-artifact-summary"><span class="hint">正在读取本次运行的产物清单…</span></div>` +
      (a.error ? `<p><span class="badge bad">${esc(a.error)}</span></p>` : '');
    engSet(engine, 'result-body', body);
    if (engine === 'unity') {
      engEl(engine, 'result-body').querySelectorAll('[data-unity-artifact-center]').forEach((button) => {
        button.onclick = () => showEngineArtifactsInCenter('unity', a.id);
      });
    }
    loadDumpPreviews(engine);
    loadEngineArtifactSummary(engine, a.id);
  } else {
    engSet(engine, 'result-body', `<p class="hint">分析进行中… 当前阶段:${esc(a.stage || '初始化')}(每 2.5s 自动刷新)</p>`);
  }
}

async function loadEngineArtifactSummary(engine, analysisId) {
  const slot = engEl(engine, 'artifact-summary');
  if (!slot || !analysisId) return;
  try {
    const manifest = await api.engineArtifacts(engine, analysisId);
    const count = (manifest.artifacts || []).length;
    const runPath = manifest.absolute_run_directory || manifest.run_directory || '';
    slot.innerHTML = `
      <span class="badge ${count ? 'ok' : 'info'}">${count ? `${count} 个已登记产物` : '本次尚无登记产物'}</span>
      <span class="hint" title="${esc(runPath)}">${esc(runPath || '运行目录已创建')}</span>
      <button data-engine-open-run title="打开本次专项分析的输出目录">打开本次输出目录</button>
      <button data-engine-show-artifacts>在产物中心查看</button>`;
    slot.querySelector('[data-engine-open-run]').onclick = () => openEngineRunFolder(engine, analysisId, slot);
    slot.querySelector('[data-engine-show-artifacts]').onclick = () => showEngineArtifactsInCenter(engine, analysisId);
  } catch (error) {
    slot.innerHTML = `<span class="badge bad">产物清单不可用</span><span class="hint">${esc(error.message || error)}</span>`;
  }
}

async function openEngineRunFolder(engine, analysisId, feedback) {
  try {
    const result = await api.openEngineRunFolder(engine, analysisId);
    if (feedback) feedback.querySelector('.hint')?.replaceChildren(document.createTextNode(`已打开: ${result.opened || ''}`));
  } catch (error) {
    if (feedback) feedback.insertAdjacentHTML('beforeend', `<span class="badge bad">${esc(error.message || error)}</span>`);
  }
}

function showEngineArtifactsInCenter(engine, analysisId) {
  const button = document.querySelector('.nav-btn[data-view="settings"]');
  if (button) button.click();
  const run = artifactRuns.find((item) => item.run_type === 'engine' && item.engine === engine && String(item.analysis_id) === String(analysisId));
  if (run) selectArtifactRun(run);
  else loadArtifactRuns({ preferred: { run_type: 'engine', engine, analysis_id: analysisId } });
}

function pollEngine(engine, id) {
  const cfg = engines[engine];
  if (cfg.timer) clearInterval(cfg.timer);
  cfg.id = id;
  const tick = async () => {
    if (cfg.id !== id) return;
    try {
      const a = await api.engineGet(engine, id);
      updateEngineUI(engine, a);
      if (a.status === 'done' || a.status === 'error') {
        clearInterval(cfg.timer);
        cfg.timer = null;
        loadEngineHistory(engine);
        loadArtifactRuns({ preferred: { run_type: 'engine', engine, analysis_id: id }, force: true, silent: true });
      }
    } catch (e) {
      engSet(engine, 'status', `<span class="badge bad">轮询失败</span> ${esc(e.message || e)}`);
    }
  };
  tick();
  cfg.timer = setInterval(tick, 2500);
}

async function startEngineAnalysis(engine, body) {
  const button = $(`#btn-${engine}-analyze`);
  setBusy(button, true, '提交中…');
  engSet(engine, 'status', '提交分析…');
  try {
    const r = await api.engineAnalyze(engine, body);
    if (r && r.id) {
      engSet(engine, 'status', `已启动 #${r.id}`);
      pollEngine(engine, r.id);
      loadEngineHistory(engine);
      loadArtifactRuns({ preferred: { run_type: 'engine', engine, analysis_id: r.id }, silent: true });
    } else {
      engSet(engine, 'status', `<span class="badge bad">启动失败</span> ${esc((r && (r.detail || r.error)) || JSON.stringify(r))}`);
    }
  } catch (e) {
    engSet(engine, 'status', `<span class="badge bad">错误</span> ${esc(e.message || e)}`);
  } finally {
    setBusy(button, false);
  }
}

/* 历史记录(查看/重跑/删除) */
async function loadEngineHistory(engine) {
  try {
    const list = await api.engineList(engine);
    const tb = engEl(engine, 'history');
    if (!list || !list.length) { tb.innerHTML = '<tr><td colspan="6" class="hint">暂无历史记录。</td></tr>'; return; }
    tb.innerHTML = list.map(a => {
      const stCls = { done: 'ok', running: 'warn', pending: 'info', error: 'bad' }[a.status] || 'info';
      return `<tr>
        <td class="mono">${esc(a.id)}</td>
        <td>${esc(a.target_name || '')}</td>
        <td>${esc(a.version || '')}</td>
        <td><span class="badge ${stCls}">${esc(a.status)}</span>${a.stage ? ` <small>${esc(a.stage)}</small>` : ''}${a.error ? `<div style="color:var(--red);font-size:11px">${esc(String(a.error).slice(0, 60))}</div>` : ''}</td>
        <td>${(a.created_at || '').slice(0, 19).replace('T', ' ')}</td>
        <td>
          <button onclick="viewEngineAnalysis('${engine}', '${esc(a.id)}')">查看</button>
          <button onclick="rerunEngineAnalysis('${engine}', '${esc(a.id)}')">重跑</button>
          <button onclick="delEngineAnalysis('${engine}', '${esc(a.id)}')">删除</button>
        </td>
      </tr>`;
    }).join('');
  } catch (e) {
    engEl(engine, 'history').innerHTML = `<tr><td colspan="6" class="table-state error">历史记录读取失败：${esc(e.message || e)}</td></tr>`;
  }
}

async function viewEngineAnalysis(engine, id) {
  try {
    const a = await api.engineGet(engine, id);
    updateEngineUI(engine, a);
    engEl(engine, 'result').scrollIntoView({ behavior: 'smooth' });
  } catch (e) {
    engSet(engine, 'status', `<span class="badge bad">读取失败</span> ${esc(e.message || e)}`);
  }
}

async function rerunEngineAnalysis(engine, id) {
  try {
    const r = await api.engineRerun(engine, id);
    if (r && r.ok) { engSet(engine, 'status', `已提交重跑 #${id}`); pollEngine(engine, id); }
    else engSet(engine, 'status', '重跑失败');
  } catch (e) { engSet(engine, 'status', '重跑失败: ' + (e.message || e)); }
}

async function delEngineAnalysis(engine, id) {
  if (!confirm(`确认删除分析记录 #${id}?`)) return;
  try {
    await api.engineDel(engine, id);
    const cfg = engines[engine];
    if (cfg.id === id) { clearInterval(cfg.timer); cfg.timer = null; cfg.id = null; }
    loadEngineHistory(engine);
  } catch (e) { engSet(engine, 'status', `<span class="badge bad">删除失败</span> ${esc(e.message || e)}`); }
}

async function loadDumpPreviews(engine) {
  document.querySelectorAll(`#${engine}-result-body pre[data-dump]`).forEach(pre => {
    const path = pre.dataset.dump;
    if (!path) { pre.textContent = '(无路径)'; return; }
    fetch('/' + path.replace(/\\/g, '/'))
      .then(r => r.text())
      .then(text => {
        const lines = text.split('\n');
        pre.textContent = lines.slice(0, 200).join('\n') + (lines.length > 200 ? `\n…(共 ${lines.length} 行,已折叠前 200 行)` : '');
      })
      .catch(() => { pre.textContent = '(无法加载 ' + path + ')'; });
  });
}

/* ---------------- UE 引擎分析 ---------------- */
async function loadUE() {
  try {
    const vs = await api.ueVersions();
    const sel = $('#ue-version');
    if (!vs || !vs.length) return;
    const isStr = typeof vs[0] === 'string';
    sel.innerHTML = vs.map(v => {
      const ver = isStr ? v : (v.version || v);
      const eng = isStr ? '' : (v.engine || '');
      return `<option value="${esc(ver)}">UE ${esc(ver)}${eng ? ' (' + esc(eng) + ')' : ''}</option>`;
    }).join('');
    showUEVersion();
  } catch (e) { engSet('ue', 'status', `<span class="badge bad">版本列表不可用</span> ${esc(e.message || e)}`); }
}

async function showUEVersion() {
  const ver = $('#ue-version').value;
  if (!ver) return;
  try {
    const v = await api.ueVersion(ver);
    const fd = v.fname_detail || {};
    $('#ue-version-info').innerHTML = [
      ['引擎版本', `${v.engine || ver}${v.family ? ' (' + v.family + ')' : ''}`],
      ['FName 索引', `${v.fname != null ? v.fname : '-'}${fd.desc ? ' — ' + fd.desc : ''}`],
      ['GObjects Chunk', v.gobjects_chunk != null ? '0x' + Number(v.gobjects_chunk).toString(16) : '-'],
      ['源码分支', esc((v.sources || {}).branch || '-')],
      ['说明', esc(v.note || '')],
    ].map(([k, x]) => `<b>${esc(k)}</b><span>${x}</span>`).join('');
  } catch (e) { $('#ue-version-info').innerHTML = `<span class="inline-state error">版本信息读取失败：${esc(e.message || e)}</span>`; }
}

$('#ue-version').onchange = showUEVersion;

$('#btn-ue-analyze').onclick = async () => {
  const body = {};
  const ver = $('#ue-version').value;
  if (ver) body.version = ver;
  const sid = $('#ue-sample-id').value.trim();
  const file = $('#ue-dump-file').files[0];
  if (sid) body.sample_id = sid;
  if (file) {
    engSet('ue', 'status', '上传 dump exe…');
    try {
      const r = await api.upload(file);
      body.sample_id = r.id;
      $('#ue-sample-id').value = r.id;
    } catch (e) {
      engSet('ue', 'status', `<span class="badge bad">上传失败</span> ${esc(e)}`);
      return;
    }
  }
  if (!body.sample_id) { setNotice('请填写样本 ID，或选择上传 dump exe 文件', 'error'); return; }
  $('#ue-dump-file').value = '';
  startEngineAnalysis('ue', body);
};

function renderUEResult(r) {
  const version = r.version;
  const verText = typeof version === 'string' ? version
    : pick(version, ['detected', 'engine_version', 'engine_family', 'version', 'label'], '未识别');
  let html = '<div class="kv">' + kvRow('引擎版本', esc(verText));
  if (version && typeof version === 'object') {
    if (version.method || version.method_name) html += kvRow('识别方式', esc(version.method || version.method_name));
    if (version.family) html += kvRow('版本族', esc(version.family));
    if (version.confidence != null) html += kvRow('置信度', esc(version.confidence));
    if (version.note) html += kvRow('说明', esc(version.note));
  }
  html += '</div>';

  const tm = (r.majors && r.majors.three_majors) || r.three_majors || (r.majors && typeof r.majors === 'object' ? r.majors : null) || {};
  html += '<h3>三大件定位</h3><table><thead><tr><th>组件</th><th>签名</th><th>目标地址(VA)</th><th>匹配地址(VA)</th></tr></thead><tbody>';
  for (const [key, label] of [['gobjects', 'GObjects'], ['gnames', 'GNames'], ['gworld', 'GWorld'], ['gengine', 'GEngine']]) {
    const h = (tm && tm[key]) || {};
    html += `<tr><td><b>${label}</b></td><td class="mono">${esc(h.name || '-')}</td>` +
      `<td class="mono">${fmtVa(h.target_va)}</td><td class="mono">${fmtVa(h.match_va)}</td></tr>`;
  }
  html += '</tbody></table>';

  const ref = r.reflection;
  if (ref && typeof ref === 'object' && Object.keys(ref).length) {
    html += '<h3>反射系统</h3><div class="kv">';
    if (ref.detected != null) html += kvRow('UObject 反射', ref.detected ? '<span class="badge ok">已检测</span>' : '<span class="badge bad">未检测</span>');
    if (ref.structures != null) html += kvRow('结构数量', esc(ref.structures));
    if (ref.confused != null) html += kvRow('反射混淆', ref.confused ? '<span class="badge bad">是</span>' : '<span class="badge ok">否</span>');
    if (ref.dump_plan) html += kvRow('Dump 方案', `<span class="mono">${esc(typeof ref.dump_plan === 'string' ? ref.dump_plan : JSON.stringify(ref.dump_plan))}</span>`);
    html += '</div>';
  }

  const enc = r.encryption;
  if (enc != null) {
    html += '<h3>加密解密</h3><div class="kv">';
    if (Array.isArray(enc)) {
      if (!enc.length) html += kvRow('加密检测', '<span class="badge ok">未检测到明显加密</span>');
      else html += kvRow('加密/混淆', enc.map(e => `<div class="sec"><b>${esc(e.name)}</b> <span class="badge ${e.risk === 'high' ? 'bad' : 'warn'}">${esc(e.risk)}</span><div style="font-size:12px;color:var(--muted)">${esc(e.detail || '')}</div></div>`).join(''));
    } else {
      const need = enc.needs_decryption;
      html += kvRow('需要解密', need ? '<span class="badge bad">是</span>' : '<span class="badge ok">否</span>');
      if (need) {
        if (enc.encryption_type || enc.type) html += kvRow('加密类型', esc(enc.encryption_type || enc.type));
        if (enc.algorithm) html += kvRow('算法', esc(enc.algorithm));
        if (enc.scheme) html += kvRow('解密方案', `<span class="mono">${esc(typeof enc.scheme === 'string' ? enc.scheme : JSON.stringify(enc.scheme))}</span>`);
        if (enc.key != null) html += kvRow('密钥', `<span class="mono">${esc(enc.key)}</span>`);
        if (enc.fname) html += kvRow('FName 解密', `<span class="mono">${esc(typeof enc.fname === 'string' ? enc.fname : JSON.stringify(enc.fname))}</span>`);
      }
      if (enc.detail) html += kvRow('说明', esc(enc.detail));
    }
    html += '</div>';
  }

  const rp = (r.report && r.report.report_paths) || r.report_paths;
  if (rp && typeof rp === 'object') {
    const links = Object.entries(rp).filter(([, v]) => v).map(([k, v]) =>
      `<a class="pkt" href="/${String(v).replace(/\\/g, '/')}" target="_blank">📄 ${esc(k)}</a>`).join('');
    if (links) html += '<h3>报告</h3><p>' + links + '</p>';
  }
  return html;
}

/* ---------------- Unity 引擎分析 ---------------- */
$('#btn-unity-analyze').onclick = async () => {
  const target_path = $('#unity-target').value.trim();
  if (!target_path) { setNotice('请输入游戏文件夹绝对路径', 'error'); return; }
  const body = { target_path };
  const v = $('#unity-version').value.trim();
  if (v) body.version = v;
  startEngineAnalysis('unity', body);
};

function unityScalar(value, fallback = '-') {
  if (value == null || value === '') return fallback;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.slice(0, 4).map((item) => unityScalar(item, '')).filter(Boolean).join(', ') || fallback;
  return String(value.value || value.name || value.path || value.file || fallback);
}

function unityStringLine(entry) {
  if (typeof entry === 'string') return entry;
  if (!entry || typeof entry !== 'object') return String(entry || '');
  const location = entry.offset != null ? `0x${Number(entry.offset).toString(16)}` : (entry.file || entry.path || '');
  const value = entry.value ?? entry.string ?? entry.text ?? entry.name ?? '';
  return `${location ? `${location} ` : ''}${typeof value === 'object' ? unityScalar(value, '') : String(value)}`.slice(0, 600);
}

function renderUnityResult(r) {
  const version = r.version || {};
  const build = r.buildtype || {};
  const scan = r.scan?.detect || {};
  const assembly = r.assembly || {};
  const resources = Array.isArray(r.resource?.resources) ? r.resource.resources : [];
  const strings = r.strings || {};
  const decrypt = r.decrypt || {};
  const sdk = r.sdk || {};
  const metadataCandidates = decrypt.metadata_candidates || scan.metadata_candidates || {};
  const candidateRows = Array.isArray(metadataCandidates.candidates) ? metadataCandidates.candidates.slice(0, 12) : [];
  const interesting = Array.isArray(strings.interesting) && strings.interesting.length
    ? strings.interesting
    : (Array.isArray(strings.strings) ? strings.strings : []);
  const allStringCount = Number(strings.count || strings.string_count || (Array.isArray(strings.strings) ? strings.strings.length : 0));
  const gameAssembly = assembly.game_assembly || assembly.gameassembly || null;
  const isMeaningfulString = (entry) => {
    const value = typeof entry === 'string' ? entry : (entry?.value ?? entry?.string ?? entry?.text ?? '');
    return /[A-Za-z]{3,}|https?:\/\/|::|[\\/_.-]/.test(String(value));
  };
  const stringPreview = interesting.filter(isMeaningfulString);
  const safeStringPreview = stringPreview.length ? stringPreview : interesting.slice(0, 120);
  const gameAssemblyPath = assembly.gameassembly_path || gameAssembly?.path || '';
  const metadataPath = assembly.metadata_path || decrypt.usable_metadata_path || decrypt.metadata || '';

  let html = '<div class="kv">';
  html += kvRow('Unity 版本', esc(version.version || version.detected_version || scan.unity_version || '未识别'));
  html += kvRow('构建类型', esc(build.build_type || assembly.mode || scan.build_type || '-'));
  if (build.confidence) html += kvRow('识别置信度', esc(build.confidence));
  if (build.note) html += kvRow('构建证据', esc(build.note));
  html += '</div>';

  html += '<h3>程序集 / IL2CPP</h3><div class="kv">';
  html += kvRow('模式', esc(assembly.mode || build.build_type || '-'));
  html += kvRow('GameAssembly.dll', esc(gameAssemblyPath || '未找到'));
  if (gameAssembly?.machine || gameAssembly?.is_64bit != null) {
    html += kvRow('架构', esc(gameAssembly.machine || (gameAssembly.is_64bit ? 'x64' : 'x86')));
  }
  if (gameAssembly?.size != null) html += kvRow('大小', esc(Number(gameAssembly.size).toLocaleString() + ' bytes'));
  if (gameAssembly?.il2cpp_export_count != null) html += kvRow('IL2CPP 导出', esc(gameAssembly.il2cpp_export_count));
  html += '</div>';
  const sections = Array.isArray(gameAssembly?.sections) ? gameAssembly.sections.slice(0, 16) : [];
  if (sections.length) {
    html += '<table><thead><tr><th>节区</th><th>VA</th><th>大小</th><th>熵</th><th>标志</th></tr></thead><tbody>' +
      sections.map((section) => `<tr><td class="mono">${esc(section.name || '')}</td><td class="mono">${esc(section.virtual_address || section.va || '')}</td><td>${esc(section.virtual_size || section.size || '')}</td><td>${esc(section.entropy ?? '')}</td><td>${esc(Array.isArray(section.flags) ? section.flags.join(', ') : (section.characteristics || ''))}</td></tr>`).join('') +
      '</tbody></table>';
  }

  html += '<h3>Metadata 状态</h3><div class="kv">';
  html += kvRow('状态', esc(decrypt.status || metadataCandidates.status || 'not_checked'));
  html += kvRow('解密状态', esc(decrypt.decryption_status || 'not_started'));
  html += kvRow('标准 Metadata', esc(metadataPath || '未找到'));
  if (decrypt.verified != null) html += kvRow('已验证明文', decrypt.verified ? '<span class="badge ok">是</span>' : '<span class="badge warn">否</span>');
  if (decrypt.decryption_required != null) html += kvRow('需要解密', decrypt.decryption_required ? '<span class="badge warn">是</span>' : '<span class="badge ok">否</span>');
  if (decrypt.recipe) html += kvRow('恢复配方', esc(decrypt.recipe));
  if (decrypt.recovery?.descriptor?.part_count != null) html += kvRow('加密分片', esc(decrypt.recovery.descriptor.part_count));
  if (decrypt.recovery?.validation?.region_count != null) html += kvRow('Metadata 表区域', esc(decrypt.recovery.validation.region_count));
  if (decrypt.recovery?.validation?.overlap_count != null) html += kvRow('区域重叠', esc(decrypt.recovery.validation.overlap_count));
  if (decrypt.note) html += kvRow('说明', esc(decrypt.note));
  if (metadataCandidates.candidate_count != null) html += kvRow('候选文件数', esc(metadataCandidates.candidate_count));
  if (metadataCandidates.candidate_summary) html += kvRow('候选摘要', esc(metadataCandidates.candidate_summary));
  html += '</div>';
  if (candidateRows.length) {
    html += '<table><thead><tr><th>候选文件</th><th>大小</th><th>熵</th><th>Magic</th><th>评级</th></tr></thead><tbody>' +
      candidateRows.map((candidate) => `<tr><td class="mono" title="${esc(candidate.path || '')}">${esc(candidate.relative_path || candidate.path || candidate.name || '')}</td><td>${esc(candidate.size ?? '')}</td><td>${esc(candidate.entropy ?? '')}</td><td>${candidate.magic_found ? '<span class="badge ok">命中</span>' : '-'}</td><td>${esc(candidate.confidence || candidate.classification || candidate.reason || '')}</td></tr>`).join('') +
      '</tbody></table>';
  }

  html += `<h3>资源 (${resources.length})</h3>`;
  if (resources.length) {
    html += '<table><thead><tr><th>文件</th><th>格式</th><th>大小</th></tr></thead><tbody>' +
      resources.slice(0, 60).map((resource) => `<tr><td class="mono" title="${esc(resource.file || resource.path || '')}">${esc(resource.file || resource.path || resource.name || '')}</td><td>${esc(resource.header || resource.type || '')}</td><td>${esc(resource.size ?? '')}</td></tr>`).join('') +
      '</tbody></table>';
    if (resources.length > 60) html += `<p class="hint">仅显示前 60 项，共 ${resources.length} 项。</p>`;
  } else html += '<p class="hint">没有可展示的资源摘要。</p>';

  html += `<h3>关键字符串 (${allStringCount.toLocaleString()})</h3>`;
  if (safeStringPreview.length) {
    html += `<p class="hint">${Array.isArray(strings.interesting) && strings.interesting.length ? '优先展示命中规则的可读字符串；' : ''}仅显示前 ${Math.min(120, safeStringPreview.length)} 项。</p>`;
    html += `<pre class="mono" style="max-height:260px">${safeStringPreview.slice(0, 120).map((entry) => esc(unityStringLine(entry))).join('\n')}</pre>`;
  } else html += '<p class="hint">没有可展示的字符串摘要。</p>';

  html += '<h3>SDK 交付</h3><div class="kv">';
  html += kvRow('状态', esc(sdk.status || (sdk.ok ? 'ready' : 'not_started')));
  if (sdk.delivery_complete != null) html += kvRow('交付完整', sdk.delivery_complete ? '<span class="badge ok">是</span>' : '<span class="badge warn">否</span>');
  if (sdk.metadata_status?.status) html += kvRow('Metadata 前置条件', esc(sdk.metadata_status.status));
  if (sdk.note) html += kvRow('原因', esc(sdk.note));
  const registration = sdk.registration || sdk.official_tool?.registration || {};
  if (registration.found) {
    html += kvRow('CodeRegistration', `<span class="mono">0x${Number(registration.code_registration).toString(16)}</span>`);
    html += kvRow('MetadataRegistration', `<span class="mono">0x${Number(registration.metadata_registration).toString(16)}</span>`);
    html += kvRow('注册地址证据', esc(`${registration.section || ''} · ${registration.candidate_count || 1} 个结构候选`));
  }
  const stats = sdk.stats || {};
  for (const [label, key] of [['类型', 'types'], ['方法', 'methods'], ['字段', 'fields'], ['枚举', 'enums']]) {
    if (stats[key] != null) html += kvRow(label, esc(stats[key]));
  }
  html += '</div>';
  if (sdk.delivery_complete) {
    html += `<table><thead><tr><th>SDK 产物</th><th>状态</th></tr></thead><tbody>
      <tr><td>Dump.cs</td><td>${sdk.dump_cs ? '<span class="badge ok">已生成</span>' : '<span class="badge bad">缺失</span>'}</td></tr>
      <tr><td>script.json</td><td>${sdk.script_json ? '<span class="badge ok">已生成</span>' : '<span class="badge bad">缺失</span>'}</td></tr>
      <tr><td>il2cpp.h</td><td>${sdk.il2cpp_h ? '<span class="badge ok">已生成</span>' : '<span class="badge bad">缺失</span>'}</td></tr>
      <tr><td>DummyDll</td><td>${(sdk.dummy_dlls || []).length ? `<span class="badge ok">${(sdk.dummy_dlls || []).length} 个 DLL</span>` : '<span class="badge bad">缺失</span>'}</td></tr>
    </tbody></table>`;
  }
  if (sdk.status === 'blocked_by_metadata') html += '<p class="hint">SDK 导出已被有意阻止，直到 Metadata 被验证为明文或经过可复现的解密验证。</p>';

  html += `<h3>交付文件</h3><p><button data-unity-artifact-center>在产物中心查看本次报告与交付文件</button></p>`;
  return html;
}

/* Legacy renderer retained for compatibility with saved browser state. The
 * active Unity engine path uses renderUnityResult above, which consumes the
 * staged result contract and keeps previews bounded. */
function renderLegacyUnityResult(r) {
  let html = '<div class="kv">';
  const ver = r.unity_version;
  const verText = typeof ver === 'string' ? ver : pick(ver, ['version', 'full', 'full_version', 'label'], '未识别');
  html += kvRow('Unity 版本', esc(verText));
  html += kvRow('构建类型', esc(r.build_type || '-'));
  html += '</div>';

  const asm = r.assembly;
  if (asm && typeof asm === 'object' && Object.keys(asm).length) {
    html += '<h3>程序集</h3>';
    const ga = pick(asm, ['game_assembly', 'gameassembly', 'GameAssembly'], null);
    if (ga && typeof ga === 'object') {
      html += '<div class="sec"><div class="sec-title">GameAssembly.dll</div><div class="kv">';
      if (ga.path || ga.pathname) html += kvRow('路径', esc(ga.path || ga.pathname));
      if (ga.arch || ga.bits) html += kvRow('架构', esc((ga.arch || '') + (ga.bits ? ' ' + ga.bits + '-bit' : '')));
      if (ga.file_size != null) html += kvRow('大小', esc(ga.file_size));
      html += '</div>';
      const sections = ga.sections || ga.section_table || [];
      if (sections.length) {
        html += '<table style="margin-top:8px"><thead><tr><th>节区</th><th>VA</th><th>大小</th><th>标志</th></tr></thead><tbody>' +
          sections.map(s => `<tr><td class="mono">${esc(s.name || '')}</td><td class="mono">${fmtVa(s.virtual_address || s.va)}</td><td>${esc(s.virtual_size || s.size || '')}</td><td>${esc((s.flags || []).join(', '))}</td></tr>`).join('') +
          '</tbody></table>';
      }
      html += '</div>';
    }
    const md = pick(asm, ['metadata', 'global_metadata', 'global-metadata'], null);
    if (md && typeof md === 'object') {
      html += '<div class="sec"><div class="sec-title">global-metadata</div><div class="kv">';
      html += kvRow('版本', esc(pick(md, ['version', 'metadata_version', 'version_string'], '-')));
      html += kvRow('类型数', esc(pick(md, ['types_count', 'type_count', 'count'], '-')));
      if (md.image_count != null) html += kvRow('镜像数', esc(md.image_count));
      if (md.method_count != null) html += kvRow('方法数', esc(md.method_count));
      if (md.field_count != null) html += kvRow('字段数', esc(md.field_count));
      if (md.string_count != null) html += kvRow('字符串数', esc(md.string_count));
      html += '</div></div>';
    }
    const ma = pick(asm, ['managed_assemblies', 'managed'], r.managed_assemblies);
    if (ma) {
      html += '<div class="sec"><div class="sec-title">Mono managed 程序集(' + (Array.isArray(ma) ? ma.length : '?') + ')</div>';
      if (Array.isArray(ma)) {
        html += '<table><thead><tr><th>程序集</th><th>大小</th></tr></thead><tbody>' +
          ma.map(m => `<tr><td class="mono">${esc(typeof m === 'string' ? m : (m.name || m.path || m.file))}</td><td>${esc(m.size != null ? m.size : (m.size_bytes || ''))}</td></tr>`).join('') +
          '</tbody></table>';
      } else {
        html += `<pre class="mono">${esc(JSON.stringify(ma, null, 1))}</pre>`;
      }
      html += '</div>';
    }
  }

  const res = r.resources || r.resource;
  if (res) {
    html += '<h3>资源(' + (Array.isArray(res) ? res.length : '') + ')</h3>';
    if (Array.isArray(res)) {
      if (!res.length) html += '<p class="hint">未发现资源</p>';
      else {
        const keys = (res[0] && typeof res[0] === 'object') ? Object.keys(res[0]) : ['值'];
        html += '<table><thead><tr>' + keys.map(k => `<th>${esc(k)}</th>`).join('') + '</tr></thead><tbody>' +
          res.map(item => typeof item === 'object'
            ? `<tr>${keys.map(k => `<td>${esc(item[k] != null ? item[k] : '')}</td>`).join('')}</tr>`
            : `<tr><td class="mono">${esc(item)}</td></tr>`).join('') +
          '</tbody></table>';
      }
    } else if (typeof res === 'object') {
      html += `<pre class="mono">${esc(JSON.stringify(res, null, 1))}</pre>`;
    }
  }

  const strs = r.strings;
  if (strs) {
    html += '<h3>字符串摘要</h3>';
    if (Array.isArray(strs)) {
      html += `<p>共 ${strs.length} 条。</p><pre class="mono" style="max-height:260px">` +
        strs.slice(0, 120).map(s => esc(typeof s === 'string' ? s : (s.offset ? s.offset + ' ' + s.value : JSON.stringify(s)))).join('\n') + '</pre>';
    } else if (typeof strs === 'object') {
      html += '<div class="kv">' + Object.entries(strs).map(([k, v]) => kvRow(k, esc(v))).join('') + '</div>';
    }
  }

  const dec = r.decrypt;
  if (dec && typeof dec === 'object') {
    html += '<h3>解密</h3><div class="kv">';
    if (dec.encrypted != null) html += kvRow('加密', dec.encrypted ? '<span class="badge bad">是</span>' : '<span class="badge ok">否</span>');
    if (dec.method || dec.method_name) html += kvRow('方法', esc(dec.method || dec.method_name));
    if (dec.algorithm) html += kvRow('算法', esc(dec.algorithm));
    if (dec.plaintext != null) html += kvRow('结果', `<span class="mono">${esc(String(dec.plaintext).slice(0, 400))}</span>`);
    if (dec.detail) html += kvRow('说明', esc(dec.detail));
    html += '</div>';
  }

  const sdk = r.sdk;
  if (sdk && typeof sdk === 'object' && Object.keys(sdk).length) {
    html += '<h3>SDK 导出</h3>';
    const stats = sdk.stats || {};
    html += '<div class="kv">';
    if (stats.types != null) html += kvRow('类型数', esc(stats.types));
    if (stats.methods != null) html += kvRow('方法数', esc(stats.methods));
    if (stats.fields != null) html += kvRow('字段数', esc(stats.fields));
    if (stats.enums != null) html += kvRow('枚举数', esc(stats.enums));
    html += '</div>';

    const dumpCs = sdk.dump_cs || sdk.dumpCs || sdk.dumpcs;
    const dumpPath = typeof dumpCs === 'string' ? dumpCs : (dumpCs && (dumpCs.path || dumpCs.pathname));
    if (dumpPath) {
      html += `<details class="fold"><summary>Dump.cs 预览(前 200 行)</summary><pre class="mono" data-dump="${esc(dumpPath)}">加载中…</pre></details>`;
    }
    const links = [];
    for (const [key, val] of [['script.json', sdk.script_json || sdk.scriptJson], ['sdk.json', sdk.sdk_json || sdk.sdkJson]]) {
      if (val) links.push(`<a class="pkt" href="/${String(val).replace(/\\/g, '/')}" target="_blank">⬇ ${key}</a>`);
    }
    if (links.length) html += '<p>' + links.join(' ') + '</p>';
  }

  const rp = (r.report && r.report.report_paths) || r.report_paths;
  if (rp && typeof rp === 'object') {
    const links = Object.entries(rp).filter(([, v]) => v).map(([k, v]) =>
      `<a class="pkt" href="/${String(v).replace(/\\/g, '/')}" target="_blank">📄 ${esc(k)}</a>`).join('');
    if (links) html += '<h3>报告</h3><p>' + links + '</p>';
  }
  return html;
}

function loadEngines() {
  loadEngineSpec('ue');
  loadEngineSpec('unity');
  loadEngineHistory('ue');
  loadEngineHistory('unity');
}

/* ---------------- MCP ---------------- */
const MCP_TOOLS = [
  ['analyze_pe', '一键全量静态分析(PE+壳+字符串)'],
  ['get_pe_info', 'PE 头/架构/子系统/安全特性'],
  ['list_sections', '节区表 + 熵 + 可疑标记'],
  ['disassemble', '按地址反汇编'],
  ['get_imports_exports', '导入/导出表'],
  ['extract_strings', '字符串提取与过滤'],
  ['detect_packer', '壳/加密封装检测'],
  ['unpack_known', '已知壳自动解压'],
  ['decompile_ghidra', 'Ghidra 反编译'],
  ['run_dynamic', '本机确认后运行 + 行为监控'],
  ['capture_network', '网络抓包 + pcap 解析'],
  ['generate_report', '生成分析报告'],
  ['run_pipeline', '运行全自动工作流'],
  ['list_samples', '样本库查询'],
  ['register_sample', '本地文件登记入库'],
];
$('#mcp-tools').innerHTML = MCP_TOOLS.map(([n, d]) =>
  `<tr><td class="mono"><b>${n}</b></td><td>${d}</td></tr>`).join('');

$('#btn-cfg-codex').onclick = () => {
  $('#cfg-out').textContent =
`# Codex 配置(项目 config.toml 或 ~/.codex/config.toml)
[mcp_servers.revlab]
command = "python"
args = ["-m", "mcp_server.server", "--port", "8765"]
env = { PYTHONPATH = "." }
# 启动 MCP: 先运行 scripts\\start-mcp.bat
`;
};
$('#btn-cfg-claude').onclick = () => {
  $('#cfg-out').textContent =
`# Claude Code 配置(项目根 .mcp.json)
{
  "mcpServers": {
    "revlab": {
      "command": "python",
      "args": ["-m", "mcp_server.server", "--port", "8765"]
    }
  }
}
# 或在 ~/.claude.json 的 mcpServers 中加入相同结构
`;
};
$('#btn-cfg-cursor').onclick = () => {
  $('#cfg-out').textContent =
`# Cursor: Settings → MCP → Add → 类型选 Command,粘贴:
python -m mcp_server.server --port 8765

# 或编辑项目 .cursor/mcp.json
{ "mcpServers": { "revlab": { "command": "python", "args": ["-m", "mcp_server.server", "--port", "8765"] } } }
`;
};
$('#btn-cfg-custom').onclick = () => {
  $('#cfg-out').textContent =
`# 自定义客户端(符合 MCP 标准均可):
# 1) 启动(HTTP 模式):
python -m mcp_server.server --port 8765
#    端点: http://127.0.0.1:8765/mcp
# 2) 或 stdio 模式:
python -m mcp_server.server --stdio
# 3) 配置中注册 endpoint/command 即可。示例 curl:
curl -X POST http://127.0.0.1:8765/mcp -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"revlab-test","version":"1.0"}}}'
`;
};

/* ---------------- Global settings, environment, and artifact center ---------------- */
function environmentJobText(status) {
  const job = status.job || {};
  if (job.status === 'running') return '正在自动配置';
  if (job.status === 'failed') return '配置失败，可重试';
  if (status.ready) return '环境已就绪';
  return `缺少 ${((status.missing || []).length || 0)} 项依赖`;
}

function renderEnvironment(status) {
  environmentSnapshot = status || {};
  const job = status.job || {};
  const summary = $('#environment-summary');
  const statusText = environmentJobText(status);
  const summaryClass = status.ready ? 'ok' : (job.status === 'running' ? 'warn' : 'bad');
  summary.className = `badge ${summaryClass}`;
  summary.textContent = statusText;

  const missing = status.missing || [];
  const missingEl = $('#environment-missing');
  if (missing.length) {
    missingEl.classList.remove('hidden');
    missingEl.innerHTML = `<b>需要准备:</b> ${missing.map(esc).join('、')}`;
  } else {
    missingEl.classList.add('hidden');
    missingEl.textContent = '';
  }

  const checks = status.checks || [];
  $('#environment-checks').innerHTML = checks.map((check) => {
    const state = check.ready ? 'ready' : (check.required ? 'missing' : 'optional');
    const label = check.ready ? '已就绪' : (check.required ? '缺失' : '可选');
    const meta = [check.version ? `版本 ${check.version}` : '', check.path || '未检测到路径'].filter(Boolean).join(' · ');
    return `<article class="environment-check ${state}">
      <div class="environment-check-head"><span class="environment-check-name">${esc(check.name || check.key)}</span><span class="badge ${check.ready ? 'ok' : (check.required ? 'bad' : 'warn')}">${label}</span></div>
      <div class="environment-check-meta" title="${esc(check.path || '')}">${esc(meta)}</div>
      <div class="environment-check-remedy">${esc(check.remedy || '')}</div>
    </article>`;
  }).join('') || '<p class="hint">未返回环境检查项目。</p>';

  const logs = job.logs || [];
  const logWrap = $('#environment-log-wrap');
  if (logs.length) {
    logWrap.classList.remove('hidden');
    logWrap.open = job.status === 'running' || job.status === 'failed';
    $('#environment-log').textContent = logs.map((entry) => `${String(entry.at || '').replace('T', ' ').slice(0, 19)}  ${entry.message || ''}`).join('\n');
  } else {
    logWrap.classList.add('hidden');
    $('#environment-log').textContent = '';
  }

  const details = [
    status.ready ? '所有必需能力均可用于执行。' : '工作流执行会在缺失组件时暂停，完成准备后可直接重试。',
    job.status && job.status !== 'idle' ? `当前任务: ${job.status}${job.return_code != null ? ` (退出码 ${job.return_code})` : ''}` : '',
  ].filter(Boolean);
  $('#environment-status').textContent = details.join(' ');
  $('#btn-environment-prepare').disabled = job.status === 'running';
  $('#btn-environment-prepare').textContent = job.status === 'running' ? '正在配置' : (status.ready ? '重新检查' : '检查并配置');
  scheduleEnvironmentRefresh(status);
}

function scheduleEnvironmentRefresh(status) {
  if (environmentTimer) {
    clearTimeout(environmentTimer);
    environmentTimer = null;
  }
  if ((status.job || {}).status === 'running') {
    environmentTimer = setTimeout(() => loadEnvironment(), 1600);
  }
}

async function loadEnvironment() {
  try {
    const status = await api.environment();
    renderEnvironment(status);
    return status;
  } catch (error) {
    $('#environment-summary').className = 'badge bad';
    $('#environment-summary').textContent = '环境状态不可用';
    $('#environment-status').textContent = String(error.message || error);
    return null;
  }
}

async function prepareEnvironment() {
  const button = $('#btn-environment-prepare');
  button.disabled = true;
  $('#environment-status').textContent = '正在请求本机环境准备…';
  try {
    const job = (environmentSnapshot || {}).job || {};
    const result = await api.prepareEnvironment(job.status === 'failed');
    renderEnvironment(result);
    $('#environment-status').textContent = result.reason === 'already_ready'
      ? '当前环境已完整配置。'
      : (result.started ? '已启动自动配置，状态会持续刷新。' : '已有环境配置任务正在运行。');
  } catch (error) {
    $('#environment-status').textContent = `环境准备请求失败: ${error.message || error}`;
    button.disabled = false;
  }
}

function artifactRunKey(run) {
  if (!run) return '';
  return run.run_type === 'engine'
    ? `engine:${run.engine}:${run.analysis_id}`
    : `graph:${run.task_id}`;
}

function artifactRunTitle(run) {
  if (run.run_type === 'engine') return `${String(run.engine || '').toUpperCase()} · ${run.name || '专项分析'}`;
  return `图工作流 · ${run.name || '未命名任务'}`;
}

function artifactRunSubTitle(run) {
  const pieces = [];
  if (run.run_type === 'engine') pieces.push(`分析 #${run.analysis_id}`);
  else pieces.push(`任务 #${run.task_id}`);
  if (run.sample_id) pieces.push(`样本 #${run.sample_id}`);
  return pieces.join(' · ');
}

function artifactStatusClass(status) {
  return { completed: 'ok', done: 'ok', running: 'warn', pending: 'info', failed: 'bad', error: 'bad', stopped: 'warn' }[status] || 'info';
}

function formatRunTime(value) {
  return String(value || '').replace('T', ' ').replace('Z', '').slice(0, 19) || '-';
}

function setArtifactStatus(message, isError = false) {
  const el = $('#artifact-status');
  if (!el) return;
  el.textContent = message || '';
  el.style.color = isError ? 'var(--red)' : '';
}

function renderArtifactRuns() {
  const table = $('#artifact-run-list');
  if (!table) return;
  const needle = String($('#artifact-search')?.value || '').trim().toLowerCase();
  const visible = artifactRuns.filter((run) => {
    if (!needle) return true;
    return [artifactRunTitle(run), artifactRunSubTitle(run), run.status, run.engine, run.sample_id].join(' ').toLowerCase().includes(needle);
  });
  if (!visible.length) {
    table.innerHTML = '<tr><td colspan="4" class="hint">没有符合条件的运行记录。</td></tr>';
    return;
  }
  const selectedKey = artifactRunKey(selectedArtifactRun);
  table.innerHTML = visible.map((run) => {
    const key = artifactRunKey(run);
    return `<tr class="artifact-run-row ${key === selectedKey ? 'selected' : ''}" data-artifact-run="${esc(key)}">
      <td><span class="artifact-run-title" title="${esc(artifactRunTitle(run))}">${esc(artifactRunTitle(run))}</span><span class="artifact-run-sub">${esc(artifactRunSubTitle(run))}</span></td>
      <td><span class="badge ${artifactStatusClass(run.status)}">${esc(run.status || 'unknown')}</span></td>
      <td>${run.manifest_ready ? esc(run.artifact_count || 0) : '<span class="hint">待读取</span>'}</td>
      <td class="mono">${esc(formatRunTime(run.created_at))}</td>
    </tr>`;
  }).join('');
  table.querySelectorAll('[data-artifact-run]').forEach((row) => {
    row.onclick = () => {
      const run = artifactRuns.find((item) => artifactRunKey(item) === row.dataset.artifactRun);
      if (run) selectArtifactRun(run);
    };
  });
}

function artifactDownloadUrl(run, artifactId) {
  const encoded = encodeURIComponent(artifactId);
  if (run.run_type === 'engine') {
    return `/api/artifacts/engine/${encodeURIComponent(run.engine)}/${encodeURIComponent(run.analysis_id)}/download/${encoded}`;
  }
  return `/api/artifacts/${encodeURIComponent(run.task_id)}/download/${encoded}`;
}

function artifactManifestTitle(manifest, run) {
  const meta = manifest.task || manifest.run || {};
  const kind = run.run_type === 'engine' ? `${String(run.engine || '').toUpperCase()} 专项分析` : '图工作流';
  return `${kind} · ${meta.name || run.name || '未命名运行'}`;
}

function renderArtifactManifest(manifest, run) {
  const detail = $('#artifact-detail');
  if (!detail) return;
  const items = manifest.artifacts || [];
  const runPath = manifest.absolute_run_directory || manifest.run_directory || '';
  const meta = manifest.task || manifest.run || {};
  const source = run.run_type === 'engine' ? `#${run.analysis_id}` : `#${run.task_id}`;
  detail.innerHTML = `
    <div class="artifact-detail-head">
      <div><h4>${esc(artifactManifestTitle(manifest, run))}</h4><p title="${esc(runPath)}">运行 ${esc(source)} · ${esc(runPath || '未提供运行目录')}</p></div>
      <div class="artifact-action-row"><button data-artifact-open-run title="打开本次运行的输出目录">打开本次目录</button></div>
    </div>
    <div class="artifact-action-row"><span class="badge ${artifactStatusClass(meta.status || run.status)}">${esc(meta.status || run.status || 'unknown')}</span><span class="hint">${items.length} 个已登记产物</span></div>
    <div class="artifact-file-list">${items.length ? items.map((artifact) => {
      const absolutePath = artifact.absolute_path || artifact.relative_path || '';
      const nodes = (artifact.source_nodes || []).filter(Boolean);
      return `<article class="artifact-file">
        <div><div class="artifact-file-name" title="${esc(absolutePath)}">${esc(artifact.name || artifact.relative_path || '未命名文件')}</div>
          <div class="artifact-file-meta">${esc(artifact.kind || 'file')} · ${Number(artifact.size || 0).toLocaleString()} bytes</div>
          <div class="artifact-file-meta">${esc(absolutePath)}</div>
          ${nodes.length ? `<div class="artifact-node-list">来源节点: ${esc(nodes.join(', '))}</div>` : ''}
        </div>
        <div class="artifact-file-actions">
          <button data-artifact-open="${esc(artifact.id)}">打开</button>
          <button data-artifact-folder="${esc(artifact.id)}">所在目录</button>
          <button data-artifact-copy="${esc(absolutePath)}">复制路径</button>
          ${artifact.is_directory ? '' : `<a href="${artifactDownloadUrl(run, artifact.id)}" download>下载</a>`}
        </div>
      </article>`;
    }).join('') : '<p class="hint">此运行尚未产生受控交付文件。完成报告、反编译、脱壳或 SDK 导出后刷新即可查看。</p>'}</div>`;

  detail.querySelector('[data-artifact-open-run]').onclick = () => openArtifactRunFolder(run);
  detail.querySelectorAll('[data-artifact-open]').forEach((button) => {
    button.onclick = () => openArtifactFile(run, button.dataset.artifactOpen, false);
  });
  detail.querySelectorAll('[data-artifact-folder]').forEach((button) => {
    button.onclick = () => openArtifactFile(run, button.dataset.artifactFolder, true);
  });
  detail.querySelectorAll('[data-artifact-copy]').forEach((button) => {
    button.onclick = () => copyArtifactPath(button.dataset.artifactCopy);
  });
}

async function selectArtifactRun(run) {
  selectedArtifactRun = run;
  renderArtifactRuns();
  const detail = $('#artifact-detail');
  detail.innerHTML = '<p class="hint">正在读取该运行的产物清单…</p>';
  try {
    const manifest = run.run_type === 'engine'
      ? await api.engineArtifacts(run.engine, run.analysis_id)
      : await api.graphArtifacts(run.task_id);
    renderArtifactManifest(manifest, run);
    setArtifactStatus(`已载入 ${artifactManifestTitle(manifest, run)}`);
  } catch (error) {
    detail.innerHTML = `<p><span class="badge bad">产物清单不可用</span> ${esc(error.message || error)}</p>`;
    setArtifactStatus(`读取产物失败: ${error.message || error}`, true);
  }
}

async function loadArtifactRunsInternal(options = {}) {
  const priorKey = artifactRunKey(selectedArtifactRun);
  const priorSnapshot = selectedArtifactRun
    ? `${selectedArtifactRun.status}:${selectedArtifactRun.manifest_ready}:${selectedArtifactRun.artifact_count || 0}`
    : '';
  setArtifactStatus('正在刷新运行记录…');
  try {
    const result = await api.artifactRuns();
    artifactRuns = result.runs || [];
    const preferred = options.preferred;
    const preferredKey = preferred ? artifactRunKey(preferred) : '';
    selectedArtifactRun = artifactRuns.find((run) => artifactRunKey(run) === preferredKey)
      || artifactRuns.find((run) => artifactRunKey(run) === priorKey)
      || artifactRuns[0]
      || null;
    const selectionChanged = artifactRunKey(selectedArtifactRun) !== priorKey;
    const currentSnapshot = selectedArtifactRun
      ? `${selectedArtifactRun.status}:${selectedArtifactRun.manifest_ready}:${selectedArtifactRun.artifact_count || 0}`
      : '';
    const runChanged = currentSnapshot !== priorSnapshot;
    renderArtifactRuns();
    if (selectedArtifactRun && (!options.silent || selectionChanged || runChanged || options.force)) {
      await selectArtifactRun(selectedArtifactRun);
    }
    else if (!selectedArtifactRun) {
      $('#artifact-detail').innerHTML = '<p class="hint">尚无工作流或专项分析运行记录。</p>';
      setArtifactStatus('尚无可读取的产物。');
    }
  } catch (error) {
    $('#artifact-run-list').innerHTML = '<tr><td colspan="4" class="hint">运行记录不可用。</td></tr>';
    $('#artifact-detail').innerHTML = `<p><span class="badge bad">无法读取产物中心</span> ${esc(error.message || error)}</p>`;
    setArtifactStatus(`读取失败: ${error.message || error}`, true);
  }
}

async function loadArtifactRuns(options = {}) {
  if (artifactRefreshInFlight) {
    artifactRefreshQueuedOptions = {
      ...(artifactRefreshQueuedOptions || {}),
      ...options,
      preferred: options.preferred || artifactRefreshQueuedOptions?.preferred,
    };
    return artifactRefreshInFlight;
  }
  artifactRefreshInFlight = loadArtifactRunsInternal(options).finally(() => {
    artifactRefreshInFlight = null;
    const queued = artifactRefreshQueuedOptions;
    artifactRefreshQueuedOptions = null;
    if (queued) loadArtifactRuns(queued);
  });
  return artifactRefreshInFlight;
}

// Keep the host artifact center in sync while a workflow iframe or an engine
// worker is producing output. The detail selection is preserved by
// loadArtifactRuns(), which resolves the previous run key on every refresh.
function stopArtifactCenterRefresh() {
  if (artifactRefreshTimer) {
    clearTimeout(artifactRefreshTimer);
    artifactRefreshTimer = null;
  }
}

function scheduleArtifactCenterRefresh() {
  stopArtifactCenterRefresh();
  if (document.hidden) return;
  artifactRefreshTimer = setTimeout(async () => {
    artifactRefreshTimer = null;
    if (!document.hidden) await loadArtifactRuns({ silent: true });
    scheduleArtifactCenterRefresh();
  }, 3500);
}

// The graph editor is same-origin and runs in an iframe. It emits lifecycle
// events so a newly-created task is visible immediately, without a manual
// page refresh or navigation to Settings.
window.addEventListener('message', (event) => {
  if (event.origin && event.origin !== window.location.origin) return;
  const message = event.data;
  if (!message || message.source !== 'revlab-workflow') return;
  const accepted = ['workflow-task-created', 'workflow-task-status', 'workflow-task-completed', 'workflow-artifacts-updated'];
  if (!accepted.includes(message.type)) return;
  const taskId = Number(message.taskId || message.task_id || 0);
  loadArtifactRuns({
    preferred: taskId ? { run_type: 'graph', task_id: taskId } : undefined,
    silent: true,
  });
});

document.addEventListener('visibilitychange', () => {
  if (document.hidden) stopArtifactCenterRefresh();
  else {
    loadArtifactRuns({ silent: true });
    scheduleArtifactCenterRefresh();
  }
});

async function openArtifactRunFolder(run) {
  try {
    const result = run.run_type === 'engine'
      ? await api.openEngineRunFolder(run.engine, run.analysis_id)
      : await api.openGraphRunFolder(run.task_id);
    setArtifactStatus(`已打开: ${result.opened || ''}`);
  } catch (error) {
    setArtifactStatus(`打开运行目录失败: ${error.message || error}`, true);
  }
}

async function openArtifactFile(run, artifactId, folder) {
  try {
    const result = run.run_type === 'engine'
      ? await api.openEngineArtifact(run.engine, run.analysis_id, artifactId, folder)
      : await api.openGraphArtifact(run.task_id, artifactId, folder);
    setArtifactStatus(`${folder ? '已打开所在目录' : '已打开文件'}: ${result.opened || ''}`);
  } catch (error) {
    setArtifactStatus(`打开产物失败: ${error.message || error}`, true);
  }
}

async function copyArtifactPath(path) {
  if (!path) return;
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(path);
    else {
      const input = document.createElement('textarea');
      input.value = path; input.style.position = 'fixed'; input.style.opacity = '0';
      document.body.appendChild(input); input.select(); document.execCommand('copy'); input.remove();
    }
    setArtifactStatus(`路径已复制: ${path}`);
  } catch (error) {
    setArtifactStatus(`复制路径失败: ${error.message || error}`, true);
  }
}

async function openConfiguredOutputRoot(feedback = $('#artifact-status')) {
  try {
    const result = await api.openOutputRoot();
    const message = `已打开产物根目录: ${result.opened || ''}`;
    if (feedback) feedback.textContent = message;
    setArtifactStatus(message);
  } catch (error) {
    const message = `打开产物根目录失败: ${error.message || error}`;
    if (feedback) feedback.textContent = message;
    setArtifactStatus(message, true);
  }
}

async function loadSettings() {
  try {
    const s = await request('/api/settings');
    $('#set-output-dir').value = s.output_dir || '';
  } catch (e) {
    $('#set-status').textContent = `设置读取失败：${e.message || e}`;
  }
  loadEnvironment();
}

$('#btn-set-save').onclick = async () => {
  const out = $('#set-output-dir').value.trim();
  const button = $('#btn-set-save');
  setBusy(button, true, '保存中…');
  try {
    const r = await request('/api/settings', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ output_dir: out }),
    });
    $('#set-status').textContent = `已保存（${r.settings.output_dir}）`;
    setNotice('输出目录设置已保存', 'success');
    if (r.ok) { loadEnvironment(); loadArtifactRuns(); }
  } catch (error) {
    $('#set-status').textContent = `保存失败：${error.message}`;
    setNotice(`输出目录保存失败：${error.message}`, 'error');
  } finally { setBusy(button, false); }
  setTimeout(() => $('#set-status').textContent = '', 3000);
};

$('#btn-environment-refresh').onclick = () => loadEnvironment();
$('#btn-environment-prepare').onclick = () => prepareEnvironment();
$('#btn-artifact-refresh').onclick = () => loadArtifactRuns();
$('#btn-artifact-output-root').onclick = () => openConfiguredOutputRoot();
$('#artifact-search').oninput = () => renderArtifactRuns();

/* ---------------- init ---------------- */
loadList();
loadStatus();
loadWorkflowUI();
loadAI();
loadUE();
loadSettings();
loadEngines();
loadArtifactRuns();
scheduleArtifactCenterRefresh();
