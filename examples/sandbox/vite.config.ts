import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: [
      {
        find: '@simplex-ts/wasm',
        replacement: fileURLToPath(new URL('../../simplex/ts/src/wasm.ts', import.meta.url)),
      },
      {
        find: /^@exowarexyz\/sdk$/,
        replacement: fileURLToPath(new URL('../../sdk/ts/dist/index.js', import.meta.url)),
      },
      {
        find: /^@qmdb-ts$/,
        replacement: fileURLToPath(new URL('../../qmdb/ts/src/index.ts', import.meta.url)),
      },
      {
        find: /^@simplex-ts$/,
        replacement: fileURLToPath(new URL('../../simplex/ts/src/index.ts', import.meta.url)),
      },
      {
        find: /^@sql-ts$/,
        replacement: fileURLToPath(new URL('../../sql/ts/src/index.ts', import.meta.url)),
      },
    ],
  },
  server: {
    fs: {
      allow: [fileURLToPath(new URL('../../..', import.meta.url))],
    },
  },
})
