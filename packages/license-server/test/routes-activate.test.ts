import { generateKeyPairSync, type KeyObject } from 'node:crypto'
import { afterEach, describe, expect, it } from 'vitest'
import { b64u, rawPublicBytes, verifyLicense, LICENSE_TTL_SECONDS } from '@sealed/license-format'
import { createApp, loadServerKeys, openStore, wrapMaster, type Store } from '../src/index.js'

function keysFromEnv() {
  const licenseKey = generateKeyPairSync('ed25519')
  const proof = generateKeyPairSync('x25519')
  const env = {
    SEALED_SERVER_LICENSE_KEY: (licenseKey.privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: (proof.privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 9)),
  }
  return { licenseKey, keys: loadServerKeys(env as NodeJS.ProcessEnv) }
}

const master = Buffer.alloc(32, 5)
const entries = [{ id: 'meta', type: 'meta', size: 1 }, { id: 'skill:translate:body', type: 'text', size: 1 }, { id: 'data:x', type: 'data', size: 1 }]

function seededStore(keys: ReturnType<typeof keysFromEnv>['keys']): Store {
  const store = openStore(':memory:')
  store.putPack({
    packId: 'com.example.p', version: '1.0.0', label: '翻译', authorPub: 'A'.repeat(43),
    masterWrapped: wrapMaster(master, keys.masterWrapKey), trialEntries: ['meta', 'skill:translate:body'], entries,
  })
  return store
}

async function post(server: import('node:http').Server, path: string, body: unknown, headers: Record<string, string> = {}) {
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('server not listening')
  const res = await fetch('http://127.0.0.1:' + address.port + path, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() as Record<string, unknown> }
}

const servers: import('node:http').Server[] = []
afterEach(() => { for (const s of servers.splice(0)) s.close() })

async function listen(app: import('node:http').Server) {
  servers.push(app)
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve))
  return app
}

const devicePub = (() => { const d = generateKeyPairSync('x25519'); return { pair: d, b64: b64u(rawPublicBytes(d.publicKey)) } })()

describe('POST /v1/trial', () => {
  it('issues a trial license granting only the pack trial entries', async () => {
    const { licenseKey, keys } = keysFromEnv()
    const store = seededStore(keys)
    const app = await listen(createApp({ store, keys, adminToken: 'admin' }))
    const res = await post(app, '/v1/trial', { device_pub: devicePub.b64, pack: { id: 'com.example.p', version: '1.0.0' } })
    expect(res.status).toBe(200)
    const payload = verifyLicense(res.body.license as string, [licenseKey.publicKey])
    expect(payload.caps).toEqual(['trial'])
    expect(payload.keys.map((k) => k.eid).sort()).toEqual(['meta', 'skill:translate:body'])
    expect(payload.exp - payload.iat).toBe(LICENSE_TTL_SECONDS)
  })

  it('refuses a second trial for the same device and pack', async () => {
    const { keys } = keysFromEnv()
    const app = await listen(createApp({ store: seededStore(keys), keys, adminToken: 'admin' }))
    const body = { device_pub: devicePub.b64, pack: { id: 'com.example.p', version: '1.0.0' } }
    expect((await post(app, '/v1/trial', body)).status).toBe(200)
    const second = await post(app, '/v1/trial', body)
    expect(second.status).toBe(409)
    expect((second.body.error as { code: string }).code).toBe('TRIAL_ALREADY_USED')
  })

  it('returns a structured 404 for an unknown pack and 400 for a malformed body', async () => {
    const { keys } = keysFromEnv()
    const app = await listen(createApp({ store: seededStore(keys), keys, adminToken: 'admin' }))
    const unknown = await post(app, '/v1/trial', { device_pub: devicePub.b64, pack: { id: 'nope', version: '1' } })
    expect(unknown.status).toBe(404)
    expect((unknown.body.error as { code: string }).code).toBe('PACK_NOT_FOUND')
    const malformed = await post(app, '/v1/trial', { device_pub: 'x', pack: { id: 'p', version: '1' } })
    expect(malformed.status).toBe(400)
    expect((malformed.body.error as { code: string }).code).toBe('BAD_REQUEST')
  })
})

describe('POST /v1/activate', () => {
  it('issues a full license within the seat limit and is idempotent for the same device', async () => {
    const { licenseKey, keys } = keysFromEnv()
    const store = seededStore(keys)
    store.putPurchase({ token: 'tok', sub: 'cust', packId: 'com.example.p', version: '1.0.0', plan: 'pro', seats: 1 })
    const app = await listen(createApp({ store, keys, adminToken: 'admin' }))
    const body = { device_pub: devicePub.b64, purchase_token: 'tok', pack: { id: 'com.example.p', version: '1.0.0' } }
    const first = await post(app, '/v1/activate', body)
    expect(first.status).toBe(200)
    const payload = verifyLicense(first.body.license as string, [licenseKey.publicKey])
    expect(payload.caps).toEqual(['full'])
    expect(payload.keys.length).toBe(3)
    const again = await post(app, '/v1/activate', body)
    expect(again.status).toBe(200)
    expect(verifyLicense(again.body.license as string, [licenseKey.publicKey]).lid).toBe(payload.lid)
    expect(store.countSeats('cust', 'com.example.p', '1.0.0')).toBe(1)
  })

  it('refuses activation beyond the seat limit and for a bad token', async () => {
    const { keys } = keysFromEnv()
    const store = seededStore(keys)
    store.putPurchase({ token: 'tok', sub: 'cust', packId: 'com.example.p', version: '1.0.0', plan: 'pro', seats: 1 })
    const other = generateKeyPairSync('x25519')
    const app = await listen(createApp({ store, keys, adminToken: 'admin' }))
    await post(app, '/v1/activate', { device_pub: devicePub.b64, purchase_token: 'tok', pack: { id: 'com.example.p', version: '1.0.0' } })
    const second = await post(app, '/v1/activate', { device_pub: b64u(rawPublicBytes(other.publicKey)), purchase_token: 'tok', pack: { id: 'com.example.p', version: '1.0.0' } })
    expect(second.status).toBe(409)
    expect((second.body.error as { code: string }).code).toBe('SEAT_LIMIT')
    const bad = await post(app, '/v1/activate', { device_pub: devicePub.b64, purchase_token: 'nope', pack: { id: 'com.example.p', version: '1.0.0' } })
    expect(bad.status).toBe(401)
    expect((bad.body.error as { code: string }).code).toBe('BAD_PURCHASE_TOKEN')
  })
})
