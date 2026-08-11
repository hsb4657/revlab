<script setup>
import { computed } from 'vue'
import { BaseEdge, EdgeLabelRenderer, getBezierPath } from '@vue-flow/core'

const props = defineProps({
  id: String,
  sourceX: Number,
  sourceY: Number,
  targetX: Number,
  targetY: Number,
  sourcePosition: String,
  targetPosition: String,
  data: Object,
  markerEnd: Object,
  selected: Boolean,
})

const [path, labelX, labelY] = getBezierPath({
  sourceX: props.sourceX,
  sourceY: props.sourceY,
  sourcePosition: props.sourcePosition,
  targetX: props.targetX,
  targetY: props.targetY,
  targetPosition: props.targetPosition,
})

const edgeStyle = computed(() => ({
  stroke: props.selected ? '#58a6ff' : '#3d4c66',
  strokeWidth: props.selected ? 2 : 1.5,
  strokeDasharray: props.data?.is_default ? '7 4' : undefined,
}))
</script>

<template>
  <BaseEdge :id="id" :path="path" :marker-end="markerEnd" :style="edgeStyle" />
  <EdgeLabelRenderer>
    <div class="edge-label" :style="{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }">
      <span v-if="data?.condition" class="el-badge el-cond" :title="data.condition">[条件] {{ data.condition }}</span>
      <span v-if="data?.is_default" class="el-badge el-default">默认</span>
    </div>
  </EdgeLabelRenderer>
</template>
