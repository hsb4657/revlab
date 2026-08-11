/* REVLab 前端逻辑 */
const $ = (sel) => document.querySelector(sel);
const api = {
  list: () => fetch('/api/samples').then(r => r.json()),
  get: (id) => fetch(`/api/samples/${id}`).then(r => r.json()),
  pipeline: (id) => fetch(`/api/samples/${id}/pipeline`).then(r => r.json()),
  upload: (file) => {
    const fd = new FormData();
    fd.append('file', file);
    return fetch('/api/samples/upload', { method: 'POST', body: fd }).then(r => r.json());
  },
  analyze: (id, wf = 'full-auto', sync = false) =>
    fetch(`/api/samples/${id}/analyze?workflow=${encodeURIComponent(wf)}&sync=${sync}`,
          { method: 'POST' }).then(r => r.json()),
  disasm: (id, addr, n) =>
    fetch(`/api/samples/${id}/disassembly?addr=${encodeURIComponent(addr)}&max_insns=${n}`).then(r => r.json()),
  status: () => fetch('/api/status').then(r => r.json()),
  wfList: () => fetch('/api/workflows').then(r => r.json()),
  wfMeta: () => fetch('/api/workflows/meta').then(r => r.json()),
  wfCreate: (d) => fetch('/api/workflows', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }).then(r => r.json()),
  wfSave: (name, d) => fetch(`/api/workflows/${name}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }).then(r => r.json()),
  wfDel: (name) => fetch(`/api/workflows/${name}`, { method: 'DELETE' }).then(r => r.json()),
  aiGet: () => fetch('/api/ai/config').then(r => r.json()),
  aiSave: (d) => fetch('/api/ai/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }).then(r => r.json()),
  aiTest: (d) => fetch('/api/ai/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) }).then(r => r.json()),
  aiChat: (msgs) => fetch('/api/ai/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ messages: msgs }) }).then(r => r.json()),
  aiSummarize: (id, prompt) => fetch(`/api/ai/summarize/${id}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ prompt }) }).then(r => r.json()),
  engineSpec: (e) => fetch(`/api/engine/${e}/spec`).then(r => r.json()),
  engineAnalyze: (e, body) => fetch(`/api/engine/${e}/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(r => r.json()),
  engineList: (e) => fetch(`/api/engine/${e}/analyses`).then(r => r.json()),
  engineGet: (e, id) => fetch(`/api/engine/${e}/analyses/${id}`).then(r => r.json()),
  engineRerun: (e, id) => fetch(`/api/engine/${e}/analyses/${id}/rerun`, { method: 'POST' }).then(r => r.json()),
  engineDel: (e, id) => fetch(`/api/engine/${e}/analyses/${id}`, { method: 'DELETE' }).then(r => r.json()),
  ueVersions: () => fetch('/api/ue/versions').then(r => r.json()),
  ueVersion: (ver) => fetch(`/api/ue/version/${encodeURIComponent(ver)}`).then(r => r.json()),
  ueSignatures: () => fetch('/api/ue/signatures').then(r => r.json()),
};

let current = null;
let pollTimer = null;
let wfMeta = {};
let currentWfName = 'full-auto';

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
  };
});

/* ---------------- 系统状态 ---------------- */
function loadStatus() {
  api.status().then(s => {
    const tags = [
      ['Ghidra', s.ghidra], ['UPX', s.upx], ['PE-sieve', s.pe_sieve],
      ['VMware', s.vmware], ['pktmon', true]
    ].map(([n, ok]) => `<span class="pkt">${n} ${ok ? '✓' : '✗'}</span>`).join('');
    $('#sys-status').innerHTML = `沙箱:${s.sandbox_mode} ${tags}`;
  }).catch(() => {});
}

/* ---------------- 样本列表 ---------------- */
async function loadList() {
  const rows = await api.list();
  const tb = $('#sample-table tbody');
  tb.innerHTML = '';
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
  } catch (e) { /* noop */ }
}

const ICONS = { identify: '🔍', unpack: '📦', disassemble: '🔬', decompile: '🧩', dynamic: '⚡', report: '📄' };
const TITLES = { identify: '识别', unpack: '脱壳', disassemble: '反汇编', decompile: '反编译', dynamic: '动态/抓包', report: '报告' };

async function renderDetail(id) {
  let s;
  try { s = await api.get(id); } catch { return; }
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
  html += `<h3>动态</h3><p>${dyn.error ? '<span class="badge bad">' + esc(dyn.error) + '</span>' : '运行 ' + ((dyn.run || {}).ran_seconds || '-') + 's,新增进程 ' + (((dyn.run || {}).behavior || {}).new_processes || []).length + ' 个'}</p>`;

  if (s.error) html += `<p class="badge bad">${esc(s.error)}</p>`;
  $('#detail-body').innerHTML = html;
}

/* ---------------- 动作 ---------------- */
$('#file-input').onchange = async (e) => {
  const files = [...e.target.files];
  $('#upload-progress').textContent = `上传 ${files.length} 个…`;
  for (const f of files) {
    try {
      const r = await api.upload(f);
      $('#upload-progress').textContent = `已上传 ${f.name} (#${r.id})`;
    } catch (err) {
      $('#upload-progress').textContent = `上传失败: ${err}`;
    }
  }
  e.target.value = '';
  loadList(); loadStatus();
};

$('#btn-refresh').onclick = () => { loadList(); loadStatus(); };

$('#btn-analyze').onclick = async () => {
  if (!current) return;
  const wf = $('#upload-workflow').value || 'full-auto';
  $('#btn-analyze').disabled = true;
  try {
    const r = await api.analyze(current, wf, false);
    alert(`已提交工作流「${r.workflow}」分析(${r.stages.join(' → ')})。后台执行,可观察上方流水线进度。`);
    setTimeout(() => { renderDetail(current); renderPipeline(current); }, 1000);
  } finally {
    $('#btn-analyze').disabled = false;
  }
};

$('#btn-disasm').onclick = async () => {
  if (!current) return;
  const s = await api.get(current);
  $('#disasm-panel').classList.remove('hidden');
  $('#disasm-addr').value = $('#disasm-addr').value || s.entry_point || '';
  await goDisasm();
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
    $('#disasm-out').textContent = '错误: ' + err;
  }
}
$('#btn-go-disasm').onclick = goDisasm;

$('#btn-report').onclick = () => {
  if (current) window.open(`/api/samples/${current}/report?fmt=html`, '_blank');
};

$('#btn-del').onclick = async () => {
  if (!current) return;
  if (!confirm('确认删除该样本及其分析记录?')) return;
  await fetch(`/api/samples/${current}`, { method: 'DELETE' });
  current = null;
  $('#sample-detail').classList.add('hidden');
  loadList();
};

/* ---------------- 工作流编辑器 ---------------- */
async function loadWorkflowUI() {
  const wfs = await api.wfList();
  wfMeta = await api.wfMeta();
  const sel = $('#wf-select');
  sel.innerHTML = wfs.map(w => `<option value="${esc(w.name)}">${esc(w.name)}${w.is_default ? ' (默认)' : ''}</option>`).join('');
  const upSel = $('#upload-workflow');
  upSel.innerHTML = wfs.map(w => `<option value="${esc(w.name)}">${esc(w.name)}${w.is_default ? ' (默认)' : ''}</option>`).join('');
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

$('#btn-wf-new').onclick = () => {
  const n = prompt('新工作流名称(英文/数字/中划线):', 'my-flow');
  if (!n) return;
  api.wfCreate({ name: n }).then(r => { if (r.ok) { currentWfName = n; loadWorkflowUI(); } else alert('创建失败: ' + (r.detail || '')); });
};

$('#btn-wf-save').onclick = async () => {
  const d = collectWorkflow();
  if (!d.name) { alert('请填写工作流名称'); return; }
  const r = await api.wfSave(d.name, d);
  if (r.ok) { $('#wf-status').textContent = '✓ 已保存'; setTimeout(() => $('#wf-status').textContent = '', 2000); loadWorkflowUI(); }
  else alert('保存失败: ' + (r.detail || ''));
};

$('#btn-wf-del').onclick = async () => {
  const w = $('#wf-select').value;
  if (!confirm(`删除工作流「${w}」?`)) return;
  const r = await api.wfDel(w);
  if (r.ok) { currentWfName = 'full-auto'; loadWorkflowUI(); } else alert(r.detail || '删除失败');
};

$('#btn-wf-toggle').onclick = async () => {
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
  const c = await api.aiGet();
  $('#ai-enabled').checked = c.enabled;
  $('#ai-base').value = c.base_url || '';
  $('#ai-key').value = c.api_key && c.api_key !== '***' ? c.api_key : '';
  $('#ai-model').value = c.model || '';
  $('#ai-temp').value = c.temperature ?? 0.2;
}
$('#btn-ai-save').onclick = async () => {
  const d = {
    enabled: $('#ai-enabled').checked,
    base_url: $('#ai-base').value.trim(),
    api_key: $('#ai-key').value.trim(),
    model: $('#ai-model').value.trim(),
    temperature: parseFloat($('#ai-temp').value || '0.2'),
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
  if (!current) { alert('请先选中样本'); return; }
  $('#ai-out').textContent = 'AI 分析中…';
  try {
    const r = await api.aiSummarize(current, $('#ai-prompt').value || '');
    $('#ai-out').textContent = r.reply;
  } catch (e) { $('#ai-out').textContent = '错误: ' + e; }
};
$('#btn-ai-send').onclick = async () => {
  const q = $('#ai-prompt').value.trim();
  if (!q) return;
  const ctx = current ? `(当前样本 #${current})` : '';
  $('#ai-out').textContent = '思考中…';
  try {
    const r = await api.aiChat([{ role: 'user', content: `${ctx} ${q}` }]);
    $('#ai-out').textContent = r.reply;
  } catch (e) { $('#ai-out').textContent = '错误: ' + e; }
};

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
  } catch (e) { /* noop */ }
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
      (a.error ? `<p><span class="badge bad">${esc(a.error)}</span></p>` : '');
    engSet(engine, 'result-body', body);
    loadDumpPreviews(engine);
  } else {
    engSet(engine, 'result-body', `<p class="hint">分析进行中… 当前阶段:${esc(a.stage || '初始化')}(每 2.5s 自动刷新)</p>`);
  }
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
      }
    } catch (e) { /* noop */ }
  };
  tick();
  cfg.timer = setInterval(tick, 2500);
}

async function startEngineAnalysis(engine, body) {
  engSet(engine, 'status', '提交分析…');
  try {
    const r = await api.engineAnalyze(engine, body);
    if (r && r.id) {
      engSet(engine, 'status', `已启动 #${r.id}`);
      pollEngine(engine, r.id);
      loadEngineHistory(engine);
    } else {
      engSet(engine, 'status', `<span class="badge bad">启动失败</span> ${esc((r && (r.detail || r.error)) || JSON.stringify(r))}`);
    }
  } catch (e) {
    engSet(engine, 'status', `<span class="badge bad">错误</span> ${esc(e)}`);
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
  } catch (e) { /* noop */ }
}

async function viewEngineAnalysis(engine, id) {
  try {
    const a = await api.engineGet(engine, id);
    updateEngineUI(engine, a);
    engEl(engine, 'result').scrollIntoView({ behavior: 'smooth' });
  } catch (e) { /* noop */ }
}

async function rerunEngineAnalysis(engine, id) {
  try {
    const r = await api.engineRerun(engine, id);
    if (r && r.ok) { engSet(engine, 'status', `已提交重跑 #${id}`); pollEngine(engine, id); }
    else engSet(engine, 'status', '重跑失败');
  } catch (e) { engSet(engine, 'status', '重跑失败: ' + e); }
}

async function delEngineAnalysis(engine, id) {
  if (!confirm(`确认删除分析记录 #${id}?`)) return;
  try {
    await api.engineDel(engine, id);
    const cfg = engines[engine];
    if (cfg.id === id) { clearInterval(cfg.timer); cfg.timer = null; cfg.id = null; }
    loadEngineHistory(engine);
  } catch (e) { /* noop */ }
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
  } catch (e) { /* noop */ }
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
  } catch (e) { /* noop */ }
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
  if (!body.sample_id) { alert('请填写样本 ID,或选择上传 dump exe 文件'); return; }
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
  if (!target_path) { alert('请输入游戏文件夹绝对路径'); return; }
  const body = { target_path };
  const v = $('#unity-version').value.trim();
  if (v) body.version = v;
  startEngineAnalysis('unity', body);
};

function renderUnityResult(r) {
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
  ['run_dynamic', '沙箱运行 + 行为监控'],
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

/* ---------------- 全局设置 ---------------- */
async function loadSettings() {
  try {
    const s = await fetch('/api/settings').then(r => r.json());
    $('#set-output-dir').value = s.output_dir || '';
  } catch (e) { /* noop */ }
}
$('#btn-set-save').onclick = async () => {
  const out = $('#set-output-dir').value.trim();
  const r = await fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ output_dir: out }),
  }).then(r => r.json());
  $('#set-status').textContent = r.ok ? `✓ 已保存 (${r.settings.output_dir})` : '保存失败';
  setTimeout(() => $('#set-status').textContent = '', 3000);
};

/* ---------------- init ---------------- */
loadList();
loadStatus();
loadWorkflowUI();
loadAI();
loadUE();
loadSettings();
loadEngines();
