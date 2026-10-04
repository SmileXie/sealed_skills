import { openStore } from './store.js'
import { loadServerKeys } from './keys.js'
import { createApp } from './app.js'

const port = Number(process.env.SEALED_SERVER_PORT ?? '8787')
const dbPath = process.env.SEALED_SERVER_DB ?? 'sealed-license-server.sqlite'
const adminToken = process.env.SEALED_SERVER_ADMIN_TOKEN
if (!adminToken) { console.error('SEALED_SERVER_ADMIN_TOKEN is required'); process.exit(1) }
const store = openStore(dbPath)
const keys = loadServerKeys(process.env)
createApp({ store, keys, adminToken }).listen(port, () => console.log('sealed license server listening on ' + port))
