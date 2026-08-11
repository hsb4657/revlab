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

/* ---------------- init ---------------- */
loadList();
loadStatus();
loadWorkflowUI();
loadAI();
