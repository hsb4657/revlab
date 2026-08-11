<script setup>
import { ref, onMounted, watch } from 'vue'
import { store, loadSpec, loadWorkflows, loadWorkflow, newWorkflow, saveWorkflow, deleteWorkflow } from './store'
import NodePalette from './components/NodePalette.vue'
import FlowCanvas from './components/FlowCanvas.vue'
import InspectorPanel from './components/InspectorPanel.vue'
import VariablesPanel from './components/VariablesPanel.vue'
import RunPanel from './components/RunPanel.vue'

const wfSelect = ref(null)
const showToast = ref(false)
let toastTimer = null

onMounted(async () => {
  try {
    await loadSpec()
    await loadWorkflows()
    if (store.workflows.length) {
      wfSelect.value = store.workflows[0].id
      await loadWorkflow(store.workflows[0].id)
    }
  } catch (e) {
    store.toast = { msg: '初始化失败: ' + e.message, type: 'err', t: Date.now() }
  }
})

async function onSelectWorkflow() {
  if (wfSelect.value == null) return
  try { await loadWorkflow(wfSelect.value) } catch (e) { alert(e.message) }
}

async function onNew() {
  await newWorkflow()
  wfSelect.value = null
}

async function onSave() {
  try {
    const id = await saveWorkflow()
    wfSelect.value = id
  } catch (e) {
    store.toast = { msg: '保存失败: ' + e.message, type: 'err', t: Date.now() }
  }
}

async function onDelete() {
  try {
    await deleteWorkflow()
    wfSelect.value = null
  } catch (e) { alert(e.message) }
}

watch(() => store.toast.t, () => {
  showToast.value = true
  if (toastTimer) clearTimeout(toastTimer)
  toastTimer = setTimeout(() => { showToast.value = false }, 2800)
})
</script>

<template>
  <div class="app">
    <header class="topbar">
      <div class="logo">REV<span>Lab</span><em>· 图化工作流</em></div>
      <input class="wf-name" v-model="store.wfName" placeholder="工作流名称(必填)" />
      <input class="wf-desc" v-model="store.wfDesc" placeholder="描述(可选)" />
      <select v-model="wfSelect" @change="onSelectWorkflow">
        <option :value="null">— 载入工作流 —</option>
        <option v-for="w in store.workflows" :key="w.id" :value="w.id">
          {{ w.name }}{{ w.is_builtin ? '(内置)' : '' }} · {{ w.node_count }}节点
        </option>
      </select>
      <div class="top-actions">
        <button @click="onNew">新建</button>
        <button class="primary" @click="onSave">保存</button>
        <button class="danger" :disabled="!store.currentId" @click="onDelete">删除</button>
      </div>
    </header>

    <div class="layout">
      <aside class="left"><NodePalette /></aside>
      <section class="center">
        <FlowCanvas />
        <RunPanel />
      </section>
      <aside class="right"><InspectorPanel /></aside>
    </div>

    <footer class="bottombar"><VariablesPanel /></footer>

    <transition name="fade">
      <div v-if="showToast" class="toast" :class="'toast-' + store.toast.type">{{ store.toast.msg }}</div>
    </transition>
  </div>
</template>
