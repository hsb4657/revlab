<script setup>
import { ref, computed, watch } from 'vue'
import { store, runWorkflow, stopWorkflow, retryNode, skipNode, switchTask, toast } from '../store'
import { api } from '../api'
import ApprovalDialog from './ApprovalDialog.vue'

const tab = ref('run')
const artifactManifest = ref(null)
const artifactLoading = ref(false)
const artifactError = ref('')

const taskStatusMap = {
  pending: '排队中',
  running: '运行中',
  completed: '已完成',
  failed: '失败',
  stopped: '已停止',
}

const tstatus = computed(() =>
  store.currentTask ? taskStatusMap[store.currentTask.status] || store.currentTask.status : '未运行',
)

const waitingApproval = computed(() => store.nodes.filter((n) => n.data.status === 'waiting_approval'))
const failedNodes = computed(() => store.nodes.filter((n) => n.data.status === 'failed'))
const skippedNodes = computed(() => store.nodes.filter((n) => n.data.status === 'skipped'))
const doneNodes = computed(() => store.nodes.filter((n) => n.data.status === 'completed'))
const runningNodes = computed(() => store.nodes.filter((n) => ['running', 'retry_waiting', 'waiting_approval'].includes(n.data.status)))
const settledCount = computed(() => store.nodes.filter((n) => ['completed', 'skipped', 'failed'].includes(n.data.status)).length)
const progress = computed(() => store.nodes.length ? Math.round((settledCount.value / store.nodes.length) * 100) : 0)

function toggleOutput(n) {
  store.output = store.output?.nodeId === n.id ? null : { nodeId: n.id, outputs: n.data.outputs }
}

async function loadArtifacts(refresh = true) {
  if (!store.currentTask?.id) {
    artifactManifest.value = null
    return
  }
  artifactLoading.value = true
  artifactError.value = ''
  try {
    artifactManifest.value = await api.artifacts(store.currentTask.id, refresh)
  } catch (error) {
    artifactError.value = error.message || 'Unable to load task artifacts'
  } finally {
    artifactLoading.value = false
  }
}

async function openArtifact(artifact, folder = false) {
  if (!store.currentTask?.id) return
  try {
    if (folder) await api.artifactFolder(store.currentTask.id, artifact.id)
    else await api.artifactOpen(store.currentTask.id, artifact.id)
  } catch (error) {
    toast(error.message || 'Artifact action failed', 'err')
  }
}

async function openRunFolder() {
  if (!store.currentTask?.id) return
  try {
    await api.artifactRunFolder(store.currentTask.id)
  } catch (error) {
    toast(error.message || 'Output folder action failed', 'err')
  }
}

async function copyArtifactPath(artifact) {
  try {
    await navigator.clipboard.writeText(artifact.absolute_path || artifact.relative_path)
    toast('Output path copied', 'ok')
  } catch (_) {
    toast('Could not copy output path', 'err')
  }
}

function showSourceNode(artifact) {
  const nodeId = (artifact.source_nodes || [])[0]
  if (!nodeId) return
  store.selectedNodeId = nodeId
  store.selectedEdgeId = null
  toast(`Source node: ${nodeId}`, 'info')
}

async function openHistoryTask(taskId) {
  await switchTask(taskId)
  tab.value = 'run'
}

watch(() => store.currentTask?.id, () => loadArtifacts(true), { immediate: true })
watch(() => store.currentTask?.status, (status) => {
  if (['completed', 'failed', 'stopped'].includes(status)) loadArtifacts(true)
})
</script>

<template>
  <div class="run-panel">
    <div class="run-tabs">
      <button :class="{ active: tab === 'run' }" @click="tab = 'run'">执行</button>
      <button :class="{ active: tab === 'history' }" @click="tab = 'history'">历史({{ store.taskHistory.length }})</button>
    </div>

    <div v-if="tab === 'run'" class="run-body">
      <div class="run-actions">
        <button class="primary" :disabled="store.running" @click="runWorkflow()">▶ 运行</button>
        <button :disabled="!store.running" @click="stopWorkflow()">⏹ 停止</button>
        <span class="task-status" :class="'ts-' + (store.currentTask?.status || 'none')">{{ tstatus }}</span>
      </div>

      <div v-if="store.currentTask" class="run-progress">
        <div class="progress-head">
          <span>任务 #{{ store.currentTask.id }}</span>
          <span>{{ settledCount }}/{{ store.nodes.length }} · {{ progress }}%</span>
        </div>
        <div class="progress-track"><span :style="{ width: progress + '%' }"></span></div>
        <div v-if="runningNodes.length" class="active-step">
          <span class="active-dot"></span>
          当前：{{ runningNodes.map((node) => node.data.label).join('、') }}
        </div>
        <div class="progress-stats">
          <span>完成 {{ doneNodes.length }}</span>
          <span>跳过 {{ skippedNodes.length }}</span>
          <span>失败 {{ failedNodes.length }}</span>
        </div>
      </div>

      <div v-if="store.currentTask" class="run-section artifacts-section">
        <div class="artifact-head">
          <span class="sec-title">产物中心</span>
          <span class="artifact-count">{{ artifactManifest?.artifacts?.length || 0 }}</span>
          <button class="icon-button" title="刷新产物" aria-label="刷新产物" :disabled="artifactLoading" @click="loadArtifacts(true)">↻</button>
          <button class="icon-button" title="打开本次运行文件夹" aria-label="打开本次运行文件夹" @click="openRunFolder">▣</button>
        </div>
        <div v-if="artifactLoading" class="hint">正在读取任务产物...</div>
        <div v-else-if="artifactError" class="artifact-error">{{ artifactError }}</div>
        <div v-else-if="!(artifactManifest?.artifacts || []).length" class="hint">该任务尚未生成可交付文件。</div>
        <div v-else class="artifact-list">
          <div v-for="artifact in artifactManifest.artifacts" :key="artifact.id" class="artifact-row">
            <span class="artifact-kind">{{ artifact.kind }}</span>
            <span class="artifact-name" :title="artifact.relative_path">{{ artifact.name }}</span>
            <span class="artifact-actions">
              <button class="icon-button" title="打开文件" aria-label="打开文件" @click.stop="openArtifact(artifact)">↗</button>
              <button class="icon-button" title="打开所在文件夹" aria-label="打开所在文件夹" @click.stop="openArtifact(artifact, true)">▣</button>
              <button class="icon-button" title="复制路径" aria-label="复制路径" @click.stop="copyArtifactPath(artifact)">⧉</button>
              <a v-if="!artifact.is_directory" class="artifact-download icon-button" :href="api.artifactDownloadUrl(store.currentTask.id, artifact.id)" title="下载文件" aria-label="下载文件">⇩</a>
              <button class="icon-button" title="显示来源节点" aria-label="显示来源节点" @click.stop="showSourceNode(artifact)">◎</button>
            </span>
          </div>
        </div>
      </div>

      <div v-if="waitingApproval.length" class="run-section">
        <div class="sec-title">待审批</div>
        <div v-for="n in waitingApproval" :key="n.id" class="run-row warn">
          <span>🛡 {{ n.data.label }}</span>
        </div>
      </div>

      <div v-if="failedNodes.length" class="run-section">
        <div class="sec-title error-title">失败节点</div>
        <div v-for="n in failedNodes" :key="n.id" class="run-row err">
          <span class="mono">{{ n.data.label }} — {{ (n.data.error || '').slice(0, 50) }}</span>
          <span class="row-actions">
            <button class="small" @click="retryNode(store.currentTask.id, n.id)">重试</button>
            <button class="small" @click="skipNode(store.currentTask.id, n.id)">跳过</button>
          </span>
        </div>
      </div>

      <div v-if="skippedNodes.length" class="run-section">
        <div class="sec-title">未进入的分支</div>
        <div v-for="n in skippedNodes" :key="n.id" class="run-row skip">
          <span class="mono">{{ n.data.label }} — 已跳过</span>
          <span class="row-actions">
            <button class="small" @click="retryNode(store.currentTask.id, n.id)">重试</button>
          </span>
        </div>
      </div>

      <div v-if="doneNodes.length" class="run-section">
        <div class="sec-title">已完成节点(点击查看输出)</div>
        <div
          v-for="n in doneNodes"
          :key="n.id"
          class="run-row done"
          @click="toggleOutput(n)"
        >
          <span class="mono">{{ n.data.label }}</span>
          <span class="run-summary">{{ n.data.outputs?.__summary || '' }}</span>
          <span class="muted small">{{ store.output?.nodeId === n.id ? '收起' : '输出' }}</span>
        </div>
      </div>

      <div v-if="store.output" class="out-view">
        <details open>
          <summary>输出 JSON ({{ store.output.nodeId }})</summary>
          <pre class="mono">{{ JSON.stringify(store.output.outputs, null, 2) }}</pre>
        </details>
      </div>

      <div v-if="store.currentTask?.error" class="run-section">
        <div class="sec-title">任务错误</div>
        <pre class="task-error mono">{{ store.currentTask.error }}</pre>
      </div>

      <ApprovalDialog />
    </div>

    <div v-if="tab === 'history'" class="run-body">
      <div v-if="!store.taskHistory.length" class="hint">暂无任务历史</div>
      <div
        v-for="t in store.taskHistory"
        :key="t.id"
        class="hist-row"
        :class="{ active: store.currentTask?.id === t.id }"
        @click="openHistoryTask(t.id)"
      >
        <span class="mono">#{{ t.id }}</span>
        <span class="hist-name">{{ t.name }}</span>
        <span class="badge" :class="'b-' + t.status">{{ taskStatusMap[t.status] || t.status }}</span>
        <span class="mono small muted">{{ (t.created_at || '').slice(0, 19).replace('T', ' ') }}</span>
      </div>
    </div>
  </div>
</template>
