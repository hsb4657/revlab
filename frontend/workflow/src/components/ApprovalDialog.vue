<script setup>
import { ref, computed, watch } from 'vue'
import { store, approveNode } from '../store'

const pending = computed(() => store.nodes.find((n) => n.data.status === 'waiting_approval') || null)
const show = computed(() => !!pending.value && !!store.currentTask)
const rejectMode = ref(false)
const reason = ref('')

watch(show, (v) => {
  if (!v) { rejectMode.value = false; reason.value = '' }
})

async function submit(approved) {
  if (!pending.value || !store.currentTask) return
  if (!approved && !rejectMode.value) {
    rejectMode.value = true
    return
  }
  await approveNode(store.currentTask.id, pending.value.id, approved, reason.value.trim())
  rejectMode.value = false
  reason.value = ''
}
</script>

<template>
  <div v-if="show" class="modal-mask">
    <div class="modal">
      <div class="modal-title">🛡 人工审批</div>
      <div class="modal-body">
        <p class="modal-node">{{ pending.data.label }} <span class="mono muted">{{ pending.id }}</span></p>
        <p class="modal-msg">{{ pending.data.params?.message || '确认继续执行下一步?' }}</p>
        <textarea v-if="rejectMode" v-model="reason" rows="2" placeholder="驳回原因(可选)"></textarea>
      </div>
      <div class="modal-actions">
        <button class="primary ok" @click="submit(true)">通过</button>
        <button class="danger" @click="submit(false)">{{ rejectMode ? '确认驳回' : '驳回' }}</button>
      </div>
    </div>
  </div>
</template>
