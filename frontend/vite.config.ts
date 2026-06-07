import { fileURLToPath, URL } from 'node:url'

import { defineConfig, type Plugin } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueDevTools from 'vite-plugin-vue-devtools'

function applyNoCacheAdminHeaders(
  req: { url?: string },
  res: { setHeader: (name: string, value: string) => void },
  next: () => void,
) {
  const path = (req.url ?? '').split('?')[0]
  if (path === '/admin' || path.startsWith('/admin/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
    res.setHeader('Pragma', 'no-cache')
    res.setHeader('Expires', '0')
  }
  next()
}

function noCacheAdminPaths(): Plugin {
  return {
    name: 'no-cache-admin-paths',
    configureServer(server) {
      server.middlewares.use(applyNoCacheAdminHeaders)
    },
    configurePreviewServer(server) {
      server.middlewares.use(applyNoCacheAdminHeaders)
    },
  }
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => ({
  plugins: [
    vue(),
    noCacheAdminPaths(),
    ...(mode === 'development' ? [vueDevTools()] : []),
  ],
  server: {
    host: '127.0.0.1',
    port: 5173
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    },
  },
}))
