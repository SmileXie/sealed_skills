import { generateKeyPairSync } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { b64u, rawPrivateBytes } from '@sealed/license-format'
import { createApp, loadServerKeys, openStore, type Store } from '../src/index.js'

const ADMIN = 'test-admin-token'
const servers: { close: () => void }[] = []
const stores: Store[] = []

function start(opts: { rateLimit?: { windowMs: number; max: number } } = {}) {
  const proof = generateKeyPairSync('x25519')
  const keys = loadServerKeys({
    SEALED_SERVER_LICENSE_KEY: (generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proof.privateKey).toString('base64url'),
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 1)),
  } as NodeJS.ProcessEnv)
  const store = openStore(':memory:')
  stores.push(store)
  const server = createApp({ store, keys, adminToken: ADMIN, ...opts })
  server.listen(0)
  servers.push(server)
  return new Promise<{ url: string; store: Store }>((resolve) => {
    server.once('listening', () => resolve({ url: 'http://127.0.0.1:' + (server.address() as AddressInfo).port, store }))
  })
}

afterEach(() => { for (const s of servers.splice(0)) s.close(); for (const s of stores.splice(0)) s.close() })

const pack = { pack: { id: 'com.example.p', version: '1' }, author_pub: 'A'.repeat(43), label: 'p', master_b64: b64u(Buffer.alloc(32, 3)), trial_entries: [], entries: [{ id: 'meta', type: 'meta', size: 1 }] }

describe('http app', () => {
  it('serves health and rejects unknown routes with a structured 404', async () => {
    const { url } = await start()
    expect(await (await fetch(url + '/v1/health')).json()).toMatchObject({ ok: true })
    const res = await fetch(url + '/v1/nope')
    expect(res.status).toBe(404)
    expect((await res.json()).error.code).toBe('BAD_REQUEST')
  })

  it('requires the admin bearer token for publishing', async () => {
    const { url } = await start()
    const unauthorized = await fetch(url + '/v1/admin/packs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(pack) })
    expect(unauthorized.status).toBe(401)
    expect((await unauthorized.json()).error.code).toBe('UNAUTHORIZED')
    const ok = await fetch(url + '/v1/admin/packs', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN }, body: JSON.stringify(pack) })
    expect(ok.status).toBe(200)
  })

  it('answers malformed JSON, oversized bodies and bad input with 4xx, never 500', async () => {
    const { url } = await start()
    const headers = { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN }
    expect((await fetch(url + '/v1/admin/packs', { method: 'POST', headers, body: '{not json' })).status).toBe(400)
    const huge = await fetch(url + '/v1/admin/packs', { method: 'POST', headers, body: 'x'.repeat(1_048_577) })
    expect(huge.status).toBe(413)
    const res = await fetch(url + '/v1/admin/packs', { method: 'POST', headers, body: JSON.stringify({ pack: { id: 'p' } }) })
    expect(res.status).toBe(400)
    expect((await res.json()).error.code).toBe('BAD_REQUEST')
  })

  it('rate-limits a burst with 429 RATE_LIMITED', async () => {
    const { url } = await start({ rateLimit: { windowMs: 60000, max: 3 } })
    const headers = { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN }
    const codes: number[] = []
    for (let i = 0; i < 5; i++) codes.push((await fetch(url + '/v1/admin/packs', { method: 'POST', headers, body: JSON.stringify(pack) })).status)
    expect(codes.filter((c) => c === 200).length).toBe(3)
    expect(codes.at(-1)).toBe(429)
  })
})
