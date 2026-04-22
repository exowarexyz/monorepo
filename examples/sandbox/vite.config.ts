import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@exoware/qmdb-web': '../../qmdb/web/src/index.ts',
      'exoware-sdk-ts': '../../sdk-ts/src/index.ts',
    },
  },
  server: {
    fs: {
      allow: [
        '../..',
        '../../sdk-ts/src',
        '../../qmdb/web/src',
      ],
    },
  },
})
