<script setup>
import { computed } from 'vue'
import { Handle, Position } from '@vue-flow/core'

const props = defineProps({
  id: String,
  data: Object,
  selected: Boolean,
})

const statusMap = {
  pending: '待执行',
  running: '执行中',
  completed: '完成',
  failed: '失败',
  skipped: '跳过',
  waiting_approval: '待审批',
  retry_waiting: '重试等待',
}

const status = computed(() => props.data?.status || 'pending')
const statusText = computed(() => statusMap[status.value] || status.value)
</script>

<template>
  <div class="rev-node" :class="['st-' + status, { selected }]">
    <Handle type="target" :position="Position.Left" />
    <div class="rev-node-head">
      <span class="rev-node-icon">{{ data.icon }}</span>
      <span class="rev-node-title">{{ data.label }}</span>
    </div>
    <div class="rev-node-sub">{{ data.nodeType }}</div>
    <div v-if="status !== 'pending'" class="rev-node-status">
      <span v-if="status === 'waiting_approval'" class="shield">🛡</span>
      {{ statusText }}
    </div>
    <div v-if="data.error" class="rev-node-err" :title="data.error">{{ data.error }}</div>
    <Handle type="source" :position="Position.Right" />
  </div>
</template>
