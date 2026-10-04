import { defineConfig } from 'vitest/config'

const NODE_SQLITE_COMPAT = '\0node-sqlite-compat'

export default defineConfig({
  plugins: [
    // vite-node 2.1.9 rewrites `node:sqlite` to the bare `sqlite` specifier, so both forms are resolved here.
    // TEST-ONLY shim: production `src/store.ts` keeps importing `node:sqlite` directly.
    {
      name: 'node-sqlite-compat',
      enforce: 'pre',
      resolveId(id) {
        if (id === 'node:sqlite' || id === 'sqlite') return NODE_SQLITE_COMPAT
      },
      load(id) {
        if (id !== NODE_SQLITE_COMPAT) return undefined
        return [
          "import { createRequire } from 'node:module'",
          'const nodeRequire = createRequire(import.meta.url)',
          'const sqlite = nodeRequire("node:sqlite")',
          'export const DatabaseSync = sqlite.DatabaseSync',
          'export default sqlite',
        ].join('\n')
      },
    },
  ],
  test: { environment: 'node' },
})
