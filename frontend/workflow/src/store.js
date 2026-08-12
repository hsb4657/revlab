import { reactive } from 'vue'
import { MarkerType } from '@vue-flow/core'
import { api } from './api'

export const store = reactive({
  spec: { node_types: [] },
  workflows: [],
  currentId: null,
  currentIsBuiltin: false,
  wfName: '',
  wfDesc: '',
  nodes: [],
  edges: [],
  variables: [],
  runtimeVals: {},
  selectedNodeId: null,
  selectedEdgeId: null,
  currentTask: null,
  contextSampleId: 0,
  taskHistory: [],
  running: false,
  output: null,
  toast: { msg: '', type: 'info', t: 0 },
})

let pollTimer = null
let lastNotifiedTaskStatus = null

function notifyHost(type, task, extra = {}) {
  try {
    if (!window.parent || window.parent === window) return
    window.parent.postMessage({
      source: 'revlab-workflow',
      type,
      workflowId: store.currentId,
      taskId: task?.id || extra.taskId || 0,
      status: task?.status || extra.status || '',
      ...extra,
    }, window.location.origin)
  } catch (_) {
    // Host notifications are optional when the editor runs standalone.
  }
}

export function toast(msg, type = 'info') {
  store.toast = { msg, type, t: Date.now() }
}

function genId(p) {
  return `${p}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`
}

function typeInfo(type) {
  return store.spec.node_types.find((t) => t.type === type) || null
}

function defaultsFor(type) {
  const t = typeInfo(type)
  const params = {}
  for (const s of (t?.params_schema || [])) params[s.key] = s.default ?? ''
  return params
}

function newVfNode(type, pos) {
  const t = typeInfo(type)
  return {
    id: genId('n'),
    type: 'wf',
    position: { x: pos.x, y: pos.y },
    data: {
      label: t?.label || type,
      nodeType: type,
      icon: t?.icon || '⚙️',
      params: defaultsFor(type),
      status: 'pending',
      outputs: null,
      error: '',
    },
  }
}

function newVfEdge(conn, isDefault) {
  return {
    id: genId('e'),
    source: conn.source,
    target: conn.target,
    type: 'wf',
    markerEnd: { type: MarkerType.ArrowClosed },
    data: { condition: '', is_default: isDefault, from: conn.source, to: conn.target },
  }
}

export function addNodeFromType(type, pos) {
  const vn = newVfNode(type, pos)
  store.nodes.push(vn)
  store.selectedNodeId = vn.id
  store.selectedEdgeId = null
}

export function addEdgeFromConnect(conn) {
  store.edges = store.edges.filter((e) => !(e.source === conn.source && e.target === conn.target))
  const src = store.nodes.find((n) => n.id === conn.source)
  const hasDefault = store.edges.some((e) => e.source === conn.source && e.data.is_default)
  const isCond = src?.data?.nodeType === 'condition'
  const ve = newVfEdge(conn, isCond && !hasDefault)
  store.edges.push(ve)
  store.selectedEdgeId = ve.id
  store.selectedNodeId = null
}

export function toVfNodes(nodes) {
  return (nodes || []).map((n) => ({
    id: n.id,
    type: 'wf',
    position: { x: n.x, y: n.y },
    data: {
      label: n.label,
      nodeType: n.type,
      icon: typeInfo(n.type)?.icon || '⚙️',
      params: { ...defaultsFor(n.type), ...(n.params || {}) },
      status: 'pending',
      outputs: null,
      error: '',
    },
  }))
}

export function toVfEdges(edges) {
  return (edges || []).map((e) => ({
    id: e.id,
    source: e.from,
    target: e.to,
    type: 'wf',
    markerEnd: { type: MarkerType.ArrowClosed },
    data: { condition: e.condition || '', is_default: !!e.is_default, from: e.from, to: e.to },
  }))
}

export function serializeNodes() {
  return store.nodes.map((vn) => ({
    id: vn.id,
    label: vn.data.label,
    type: vn.data.nodeType,
    params: vn.data.params || {},
    x: Math.round(vn.position.x),
    y: Math.round(vn.position.y),
  }))
}

export function serializeEdges() {
  return store.edges.map((ve) => {
    const e = { id: ve.id, from: ve.source, to: ve.target }
    if (ve.data?.condition) e.condition = ve.data.condition
    if (ve.data?.is_default) e.is_default = true
    return e
  })
}

export async function loadSpec() {
  store.spec = await api.spec()
}

export async function loadWorkflows() {
  store.workflows = await api.list()
}

export function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
  store.running = false
}

export function clearEditor() {
  stopPolling()
  store.currentId = null
  store.currentIsBuiltin = false
  store.wfName = ''
  store.wfDesc = ''
  store.nodes = []
  store.edges = []
  store.variables = []
  store.runtimeVals = {}
  store.selectedNodeId = null
  store.selectedEdgeId = null
  store.currentTask = null
  store.taskHistory = []
  store.output = null
}

export async function newWorkflow() {
  clearEditor()
  store.wfName = '未命名工作流'
  toast('已新建工作流', 'ok')
}

export async function loadWorkflow(id) {
  clearEditor()
  const wf = await api.get(id)
  store.currentId = wf.id
  store.currentIsBuiltin = !!wf.is_builtin
  store.wfName = wf.name
  store.wfDesc = wf.description || ''
  store.nodes = toVfNodes(wf.nodes || [])
  store.edges = toVfEdges(wf.edges || [])
  store.variables = (wf.variables || []).map((v) => ({ ...v }))
  await refreshTasks()
}

export async function saveWorkflow() {
  const body = {
    name: store.wfName,
    description: store.wfDesc,
    nodes: serializeNodes(),
    edges: serializeEdges(),
    variables: store.variables,
  }
  const v = await api.validate(body.nodes, body.edges, body.variables)
  if (!v.valid && v.errors?.length) {
    const msg = '图校验未通过:\n- ' + v.errors.join('\n- ') + '\n\n仍然强制保存?'
    if (!window.confirm(msg)) {
      toast('已取消保存', 'err')
      return null
    }
  }
  let id = store.currentId
  if (id) {
    await api.update(id, body)
  } else {
    const r = await api.create(body)
    id = r.id
    store.currentId = id
  }
  await loadWorkflows()
  toast('已保存', 'ok')
  return id
}

export async function deleteWorkflow() {
  if (!store.currentId) return
  if (!window.confirm(`确认删除工作流「${store.wfName}」?`)) return
  await api.remove(store.currentId)
  await loadWorkflows()
  clearEditor()
  toast('已删除', 'ok')
}

function applyTaskStates(states) {
  const st = states || {}
  for (const vn of store.nodes) {
    const s = st[vn.id]
    vn.data.status = s?.status || 'pending'
    vn.data.outputs = s?.outputs || null
    vn.data.error = s?.error || ''
  }
  store.output = null
}

export async function refreshTasks() {
  if (!store.currentId) return
  store.taskHistory = await api.listTasks(store.currentId)
  const active = store.taskHistory.find((task) => ['running', 'pending'].includes(task.status))
  if (active && (!store.currentTask || store.currentTask.id !== active.id)) {
    store.currentTask = active
    applyTaskStates(active.node_states || {})
    startPolling(active.id)
  }
}

export function startPolling(tid) {
  stopPolling()
  store.running = true
  lastNotifiedTaskStatus = null
  const tick = async () => {
    try {
      const t = await api.getTask(store.currentId, tid)
      store.currentTask = t
      applyTaskStates(t.node_states || {})
      const terminal = ['completed', 'failed', 'stopped'].includes(t.status)
      if (t.status !== lastNotifiedTaskStatus) {
        lastNotifiedTaskStatus = t.status
        notifyHost(terminal ? 'workflow-task-completed' : 'workflow-task-status', t)
      }
      if (terminal) {
        stopPolling()
        await refreshTasks()
      }
    } catch (e) {
      stopPolling()
      toast('任务查询失败: ' + e.message, 'err')
    }
  }
  tick()
  pollTimer = setInterval(tick, 1000)
}

async function refreshCurrent() {
  if (!store.currentTask) return
  const t = await api.getTask(store.currentId, store.currentTask.id)
  store.currentTask = t
  applyTaskStates(t.node_states || {})
}

export async function runWorkflow() {
  let id = store.currentId
  if (!id) {
    toast('尚未保存,先自动保存…', 'info')
    id = await saveWorkflow()
    if (!id) return
  }
  const vals = {}
  for (const v of store.variables) {
    const rv = store.runtimeVals[v.key]
    if (v.key && rv !== undefined && rv !== '') vals[v.key] = rv
  }
  const r = await api.createTask(id, {
    name: `${store.wfName}#${Date.now().toString().slice(-6)}`,
    variables: vals,
    sample_id: store.contextSampleId || 0,
  })
  const tid = r.id
  notifyHost('workflow-task-created', { id: tid, status: 'pending' })
  for (const vn of store.nodes) { vn.data.status = 'pending'; vn.data.outputs = null; vn.data.error = '' }
  store.currentTask = null
  store.output = null
  await api.runTask(id, tid)
  notifyHost('workflow-task-status', { id: tid, status: 'running' })
  startPolling(tid)
  await refreshTasks()
  toast('任务已启动', 'ok')
}

export async function stopWorkflow() {
  if (!store.currentTask || !store.currentId) return
  await api.stopTask(store.currentId, store.currentTask.id)
  stopPolling()
  await refreshCurrent()
  notifyHost('workflow-task-completed', store.currentTask)
  await refreshTasks()
  toast('已发送停止', 'ok')
}

export async function approveNode(tid, nodeId, approved, reason) {
  await api.approve(tid, nodeId, { approved, reason })
  await refreshCurrent()
  toast(approved ? '已通过审批' : '已驳回', 'ok')
}

export async function retryNode(tid, nodeId) {
  await api.retry(tid, nodeId)
  toast('已触发重试', 'ok')
  store.running = true
  startPolling(tid)
}

export async function skipNode(tid, nodeId) {
  await api.skip(tid, nodeId)
  await refreshCurrent()
  toast('已跳过节点', 'ok')
}

export async function switchTask(tid) {
  stopPolling()
  const t = await api.getTask(store.currentId, tid)
  store.currentTask = t
  applyTaskStates(t.node_states || {})
  if (['running', 'pending'].includes(t.status)) startPolling(tid)
}
