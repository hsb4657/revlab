<script setup>
import { ref, computed } from 'vue'
import { store, runWorkflow, stopWorkflow, retryNode, skipNode, switchTask } from '../store'
import ApprovalDialog from './ApprovalDialog.vue'

const tab = ref('run')

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

function toggleOutput(n) {
  store.output = store.output?.nodeId === n.id ? null : { nodeId: n.id, outputs: n.data.outputs }
}
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

      <div v-if="waitingApproval.length" class="run-section">
        <div class="sec-title">待审批</div>
        <div v-for="n in waitingApproval" :key="n.id" class="run-row warn">
          <span>🛡 {{ n.data.label }}</span>
        </div>
      </div>

      <div v-if="failedNodes.length || skippedNodes.length" class="run-section">
        <div class="sec-title">异常节点</div>
        <div v-for="n in failedNodes" :key="n.id" class="run-row err">
          <span class="mono">{{ n.data.label }} — {{ (n.data.error || '').slice(0, 50) }}</span>
          <span class="row-actions">
            <button class="small" @click="retryNode(store.currentTask.id, n.id)">重试</button>
            <button class="small" @click="skipNode(store.currentTask.id, n.id)">跳过</button>
          </span>
        </div>
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
        @click="switchTask(t.id)"
      >
        <span class="mono">#{{ t.id }}</span>
        <span class="hist-name">{{ t.name }}</span>
        <span class="badge" :class="'b-' + t.status">{{ taskStatusMap[t.status] || t.status }}</span>
        <span class="mono small muted">{{ (t.created_at || '').slice(0, 19).replace('T', ' ') }}</span>
      </div>
    </div>
  </div>
</template>
