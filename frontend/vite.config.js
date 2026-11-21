import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/static/',
  build: { outDir: '../static', emptyOutDir: true, chunkSizeWarningLimit: 1500 },
  // asi/domain.json (reguły domenowe) leży poza frontend/ - współdzielony z backendem
  server: { proxy: { '/api': 'http://127.0.0.1:8000' }, fs: { allow: ['..'] } },
})
