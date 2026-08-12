<script setup>
import { store } from '../store'

function addVar() {
  store.variables.push({ key: '', name: '', type: 'text', default: '', required: false, source_type: 'input' })
}

function delVar(i) {
  store.variables.splice(i, 1)
}
</script>

<template>
  <div class="variables-panel">
    <div class="vp-head">
      <div class="vp-title">工作流变量</div>
      <button class="small" @click="addVar">+ 新增变量</button>
    </div>
    <table v-if="store.variables.length" class="vp-table">
      <thead>
        <tr>
          <th>Key</th><th>名称</th><th>类型</th><th>默认值</th><th>来源</th><th>必填</th><th>运行值</th><th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(v, i) in store.variables" :key="i">
          <td><input v-model="v.key" placeholder="sample_path" class="mono" /></td>
          <td><input v-model="v.name" placeholder="样本路径" /></td>
          <td>
            <select v-model="v.type">
              <option value="text">文本</option>
              <option value="number">数字</option>
              <option value="bool">布尔</option>
            </select>
          </td>
          <td><input v-model="v.default" /></td>
          <td>
            <select v-model="v.source_type">
              <option value="input">输入</option>
              <option value="output">输出</option>
            </select>
          </td>
          <td><input type="checkbox" v-model="v.required" /></td>
          <td>
            <span v-if="store.contextSampleId && v.key === 'sample_path'" class="injected-value">
              自动使用样本 #{{ store.contextSampleId }}
            </span>
            <input v-else-if="v.source_type === 'input'" v-model="store.runtimeVals[v.key]" placeholder="运行前填入" class="mono" />
            <span v-else class="muted small">—</span>
          </td>
          <td><button class="small danger" @click="delVar(i)" title="删除">✕</button></td>
        </tr>
      </tbody>
    </table>
    <p v-else class="hint vp-empty">暂无变量。可添加 sample_path 等输入变量,运行前填入值(通过 {{变量}} 占位符引用)。</p>
  </div>
</template>
