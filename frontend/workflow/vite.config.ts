import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  base: '/wf/',
  plugins: [vue()],
  build: {
    outDir: '../wf-dist',
    emptyOutDir: true,
  },
})
