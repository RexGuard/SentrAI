import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

// The core is reached through /api, so the session cookie stays on this page's own address.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const core = env.VITE_CORE_URL || 'http://127.0.0.1:8000'
  return {
    plugins: [react(), tailwindcss()],
    server: {
      proxy: { '/api': { target: core, changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, '') } },
    },
  }
})
