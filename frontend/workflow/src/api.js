async function j(method, url, body) {
  const opt = { method, headers: { 'Content-Type': 'application/json' } }
  if (body !== undefined) opt.body = JSON.stringify(body)
  const r = await fetch(url, opt)
  let data = null
  try { data = await r.json() } catch (_) { /* empty */ }
  if (!r.ok) {
    const msg = data?.detail || data?.message || JSON.stringify(data) || r.statusText
    throw new Error(msg)
  }
  return data
}

export const api = {
  spec: () => j('GET', '/api/wf2/spec'),
  validate: (nodes, edges) => j('POST', '/api/wf2/validate', { nodes, edges }),
  list: () => j('GET', '/api/wf2'),
  get: (id) => j('GET', `/api/wf2/${id}`),
  create: (b) => j('POST', '/api/wf2', b),
  update: (id, b) => j('PUT', `/api/wf2/${id}`, b),
  remove: (id) => j('DELETE', `/api/wf2/${id}`),
  createTask: (wfid, b) => j('POST', `/api/wf2/${wfid}/tasks`, b || {}),
  runTask: (wfid, tid) => j('POST', `/api/wf2/${wfid}/tasks/${tid}/run`),
  stopTask: (wfid, tid) => j('POST', `/api/wf2/${wfid}/tasks/${tid}/stop`),
  listTasks: (wfid) => j('GET', `/api/wf2/${wfid}/tasks?limit=100`),
  getTask: (wfid, tid) => j('GET', `/api/wf2/${wfid}/tasks/${tid}`),
  retry: (tid, nid) => j('POST', `/api/wf2/tasks/${tid}/nodes/${nid}/retry`),
  skip: (tid, nid) => j('POST', `/api/wf2/tasks/${tid}/nodes/${nid}/skip`),
  approve: (tid, nid, b) => j('POST', `/api/wf2/tasks/${tid}/nodes/${nid}/resolve-approval`, b),
}
