<script setup>
import { computed, watch } from 'vue'
import { store } from '../store'

const selectedNode = computed(() => store.nodes.find((n) => n.id === store.selectedNodeId) || null)
const selectedEdge = computed(() => store.edges.find((e) => e.id === store.selectedEdgeId) || null)

const schema = computed(() => {
  const n = selectedNode.value
  if (!n) return []
  return store.spec.node_types.find((t) => t.type === n.data.nodeType)?.params_schema || []
})

function optionLabel(value) {
  return ({
    auto: '自动选择隔离', sandboxie: 'Sandboxie-Plus（轻量）',
    windows_sandbox: 'Windows Sandbox', vmware: 'VMware（手动）',
    host: '宿主机（需确认）',
  })[value] || value
}

watch(selectedNode, (n) => {
  if (!n) return
  const p = n.data.params
  p.on_fail = p.on_fail ?? 'abort'
  p.retry_count = p.retry_count ?? 0
  for (const f of schema.value) {
    if (!(f.key in p)) p[f.key] = f.default ?? ''
  }
}, { immediate: true, deep: true })
</script>

<template>
  <div class="inspector">
    <template v-if="selectedNode">
      <div class="insp-head">
        <span class="insp-icon">{{ selectedNode.data.icon }}</span>
        <h3>{{ selectedNode.data.label }}</h3>
        <span class="insp-type mono">{{ selectedNode.data.nodeType }}</span>
      </div>
      <div class="insp-body">
        <label class="field">
          <span class="flabel">节点名称</span>
          <input v-model="selectedNode.data.label" />
        </label>
        <div class="field-row">
          <label class="field half">
            <span class="flabel">失败策略</span>
            <select v-model="selectedNode.data.params.on_fail">
              <option value="abort">中止任务</option>
              <option value="skip">跳过</option>
              <option value="retry">自动重试</option>
            </select>
          </label>
          <label class="field half">
            <span class="flabel">重试次数</span>
            <input type="number" v-model.number="selectedNode.data.params.retry_count" />
          </label>
        </div>
        <div class="params-sec">
          <div class="sec-title">参数</div>
          <div v-if="!schema.length" class="hint">该节点无参数</div>
          <label v-for="f in schema" :key="f.key" class="field">
            <span class="flabel">
              {{ f.label }}<span v-if="f.required" class="req">*</span>
            </span>
            <span v-if="f.type === 'select'">
              <select v-model="selectedNode.data.params[f.key]">
                <option v-for="o in (f.options || [])" :key="o" :value="o">{{ optionLabel(o) }}</option>
              </select>
            </span>
            <span v-else-if="f.type === 'bool'">
              <label class="inline-check">
                <input type="checkbox" v-model="selectedNode.data.params[f.key]" />
                <span>{{ selectedNode.data.params[f.key] ? '是' : '否' }}</span>
              </label>
            </span>
            <span v-else-if="f.type === 'number'">
              <input type="number" v-model.number="selectedNode.data.params[f.key]" />
            </span>
            <span v-else-if="f.type === 'textarea'">
              <textarea rows="4" v-model="selectedNode.data.params[f.key]"></textarea>
            </span>
            <span v-else>
              <input type="text" v-model="selectedNode.data.params[f.key]" />
            </span>
            <div v-if="f.desc" class="field-desc">{{ f.desc }}</div>
          </label>
        </div>
      </div>
    </template>

    <template v-else-if="selectedEdge">
      <div class="insp-head">
        <h3>边配置</h3>
        <span class="insp-type mono">{{ selectedEdge.source }} → {{ selectedEdge.target }}</span>
      </div>
      <div class="insp-body">
        <label class="field">
          <span class="flabel">条件表达式</span>
          <input v-model="selectedEdge.data.condition" placeholder="例: {{packer_detect.packed}} == true" />
        </label>
        <label class="inline-check field">
          <input type="checkbox" v-model="selectedEdge.data.is_default" />
          <span>默认分支</span>
        </label>
        <p class="hint">条件节点的出边可配置分支条件与默认分支;勾选「默认」后,无任何条件匹配时走该边。</p>
      </div>
    </template>

    <div v-else class="insp-empty">
      <div class="insp-empty-icon">🖱</div>
      <p>选中节点或边后<br />在此编辑参数</p>
      <p class="hint">双击节点打开参数面板 · 点击边编辑条件分支</p>
    </div>
  </div>
</template>
