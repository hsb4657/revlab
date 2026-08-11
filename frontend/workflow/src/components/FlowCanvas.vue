<script setup>
import { ref } from 'vue'
import { VueFlow } from '@vue-flow/core'
import { Background, BackgroundVariant } from '@vue-flow/background'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import FlowNode from './FlowNode.vue'
import FlowEdge from './FlowEdge.vue'
import { store, addNodeFromType, addEdgeFromConnect } from '../store'

const flow = ref(null)

function onInit(instance) {
  flow.value = instance
}

function onConnect(conn) {
  addEdgeFromConnect(conn)
}

function onNodeClick(_e, node) {
  store.selectedNodeId = node.id
  store.selectedEdgeId = null
}

function onNodeDbl(_e, node) {
  store.selectedNodeId = node.id
  store.selectedEdgeId = null
}

function onEdgeClick(_e, edge) {
  store.selectedEdgeId = edge.id
  store.selectedNodeId = null
}

function onPaneClick() {
  store.selectedNodeId = null
  store.selectedEdgeId = null
}

function onNodesDelete() {
  if (!store.nodes.some((n) => n.id === store.selectedNodeId)) store.selectedNodeId = null
}

function onEdgesDelete() {
  if (!store.edges.some((e) => e.id === store.selectedEdgeId)) store.selectedEdgeId = null
}

function onDragOver(e) {
  e.preventDefault()
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'move'
}

function onDrop(e) {
  const type = e.dataTransfer?.getData('application/revlab-node')
  if (!type) return
  e.preventDefault()
  const pos = flow.value?.screenToFlowCoordinate({ x: e.clientX, y: e.clientY }) || { x: e.clientX, y: e.clientY }
  addNodeFromType(type, pos)
}
</script>

<template>
  <div class="canvas-wrap" @dragover="onDragOver" @drop="onDrop">
    <VueFlow
      v-model:nodes="store.nodes"
      v-model:edges="store.edges"
      :default-viewport="{ x: 0, y: 0, zoom: 0.9 }"
      :min-zoom="0.2"
      :max-zoom="3"
      :delete-key-code="['Backspace', 'Delete']"
      @init="onInit"
      @connect="onConnect"
      @node-click="onNodeClick"
      @node-double-click="onNodeDbl"
      @edge-click="onEdgeClick"
      @edge-double-click="onEdgeClick"
      @pane-click="onPaneClick"
      @nodes-delete="onNodesDelete"
      @edges-delete="onEdgesDelete"
    >
      <Background :variant="BackgroundVariant.Dots" :gap="20" :size="1.5" color="#1a2233" />
      <Controls position="bottom-left" />
      <MiniMap
        position="bottom-right"
        :pannable="true"
        :zoomable="true"
        node-color="#1c2437"
        node-stroke-color="#58a6ff"
        mask-color="rgba(11,15,26,.6)"
      />
      <template #node-wf="p"><FlowNode v-bind="p" /></template>
      <template #edge-wf="p"><FlowEdge v-bind="p" /></template>
    </VueFlow>
    <div class="canvas-hint">双击节点编辑参数 · 从左侧拖拽节点到画布 · 条件节点出边可配置分支</div>
  </div>
</template>
