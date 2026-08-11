<script setup>
import { computed } from 'vue'
import { store, addNodeFromType } from '../store'

const groups = computed(() => {
  const g = {}
  for (const t of store.spec.node_types || []) {
    const c = t.category || '通用'
    if (!g[c]) g[c] = []
    g[c].push(t)
  }
  return g
})

function onClick(t) {
  addNodeFromType(t.type, { x: 60 + Math.random() * 120, y: 60 + Math.random() * 120 })
}

function onDragStart(e, type) {
  e.dataTransfer.setData('application/revlab-node', type)
  e.dataTransfer.effectAllowed = 'move'
}
</script>

<template>
  <div class="palette">
    <div class="palette-title">节点库</div>
    <div v-for="(items, cat) in groups" :key="cat" class="palette-group">
      <div class="palette-cat">{{ cat }}</div>
      <div
        v-for="t in items"
        :key="t.type"
        class="palette-item"
        draggable="true"
        @click="onClick(t)"
        @dragstart="onDragStart($event, t.type)"
      >
        <span class="pi-icon">{{ t.icon }}</span>
        <div class="pi-text">
          <div class="pi-label">{{ t.label }}</div>
          <div class="pi-type">{{ t.type }}</div>
        </div>
      </div>
    </div>
    <p class="hint" style="padding: 10px 14px">点击或拖拽到画布添加节点</p>
  </div>
</template>
