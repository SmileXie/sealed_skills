import { generateKeyPairSync } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { b64u, rawPrivateBytes, rawPublicBytes, signLicense, type LicensePayload } from '@sealed/license-format'
import { LicenseClient, type LicenseClientOptions } from '../src/index.js'

const T0_SECONDS = 1_700_000_000
const T0_MS = T0_SECONDS * 1000
const PACK = { id: 'com.example.p', version: '1.0.0' }
type Queued = { status: number; body: unknown } | 'throw'

function createFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'sealed-home-'))
  const signingKey = generateKeyPairSync('ed25519')
  const device = generateKeyPairSync('x25519')
  const privRaw = rawPrivateBytes(device.privateKey)
  const devicePub = rawPublicBytes(device.publicKey).toString('base64url')
  const responses: Queued[] = []
  const calls: Queued[] = []
  let nowMs = T0_MS
  const fetchFn = (async () => {
    const next = responses[calls.length] ?? 'throw'
    calls.push(next)
    if (next === 'throw') throw new Error('network down')
    return new Response(JSON.stringify(next.body), { status: next.status, headers: { 'content-type': 'application/json' } })
  }) as unknown as typeof fetch
  const keystore = {
    async loadDevicePrivateKey() { return Buffer.from(privRaw) },
    async loadDevicePublicKey() { return rawPublicBytes(device.publicKey) },
    async createDeviceKey() {},
    async deleteDeviceKey() {},
  }
  const opts: LicenseClientOptions = {
    serverUrl: 'http://127.0.0.1:1',
    serverProofPubB64: b64u(rawPublicBytes(generateKeyPairSync('x25519').publicKey)),
    keystore, homeDir: dir, trustedLicenseKeys: [signingKey.publicKey],
    fetchFn, now: () => nowMs, retry: { attempts: 2, baseMs: 1, maxMs: 2 },
  }
  const license = (over: Partial<{ lid: string; iat: number; expOffset: number; pack: LicensePayload['pack']; dev: string }> = {}) =>
    signLicense({
      v: 1, lid: over.lid ?? 'lic_1', sub: 'cust', pack: over.pack ?? { ...PACK, author_pub: 'A'.repeat(43) },
      dev: over.dev ?? devicePub, iat: over.iat ?? T0_SECONDS, exp: (over.iat ?? T0_SECONDS) + (over.expOffset ?? 604800),
      grace_until: (over.iat ?? T0_SECONDS) + (over.expOffset ?? 604800) + 259200,
      caps: ['full'], groups: ['pro'], keys: [], seats: { plan: 'pro', limit: 1 },
    }, signingKey.privateKey)
  return {
    dir, calls, license, devicePub,
    client: new LicenseClient(opts),
    setNow: (ms: number) => { nowMs = ms },
    respond: (...next: Queued[]) => { responses.splice(0, responses.length, ...next); calls.length = 0 },
    writeCached: (text: string, lid = 'lic_1') => writeFileSync(join(dir, 'licenses', lid + '.license.json'), text),
    cachedPath: (lid = 'lic_1') => join(dir, 'licenses', lid + '.license.json'),
  }
}

describe('LicenseClient', () => {
  it('returns a cached active license without touching the network', async () => {
    const f = createFixture()
    f.writeCached(f.license())
    const ent = await f.client.ensureLicense(PACK)
    expect(ent.state).toBe('active')
    expect(ent.source).toBe('cache')
    expect(f.calls.length).toBe(0)
  })

  it('stays usable in grace offline and never mutates state on a network failure', async () => {
    const f = createFixture()
    f.respond('throw')
    // 过期但仍在 3 天宽限期内（exp = iat，grace_until = iat + 259200）。
    const text = f.license({ iat: T0_SECONDS - 86400, expOffset: 0 })
    f.writeCached(text)
    const ent = await f.client.ensureLicense(PACK)
    expect(ent.state).toBe('grace')
    expect(ent.source).toBe('cache')
    expect(readFileSync(f.cachedPath(), 'utf8')).toBe(text)
    expect(existsSync(join(f.dir, 'clock.json'))).toBe(false)
  })

  it('renews an expired license online and writes the new license', async () => {
    const f = createFixture()
    const fresh = f.license({ lid: 'lic_old', iat: T0_SECONDS, expOffset: 604800 })
    f.respond({ status: 200, body: { license: fresh } })
    f.writeCached(f.license({ lid: 'lic_old', iat: T0_SECONDS - 604800 - 259200 - 10, expOffset: 0 }), 'lic_old')
    const ent = await f.client.ensureLicense(PACK)
    expect(ent.state).toBe('active')
    expect(ent.source).toBe('network')
    expect(readFileSync(f.cachedPath('lic_old'), 'utf8')).toBe(fresh)
  })

  it('removes the cached license and denies when the server reports REVOKED', async () => {
    const f = createFixture()
    f.respond({ status: 403, body: { error: { code: 'REVOKED', message: 'revoked' } } })
    f.writeCached(f.license({ iat: T0_SECONDS - 604800 - 259200 - 10, expOffset: 0 }))
    await expect(f.client.ensureLicense(PACK)).rejects.toMatchObject({ code: 'LICENSE_REVOKED' })
    expect(existsSync(f.cachedPath())).toBe(false)
  })

  it('denies with CLOCK_UNTRUSTED when the clock rolled back and the server is unreachable', async () => {
    const f = createFixture()
    // 先导入 license 以建立 clock.json 锚点（accept 会写入 payload.iat）。
    await f.client.importLicense(f.license())
    f.respond('throw')
    f.setNow(T0_MS - 3_600_000)
    await expect(f.client.ensureLicense(PACK)).rejects.toMatchObject({ code: 'CLOCK_UNTRUSTED' })
  })

  it('retries a 5xx and succeeds on the next attempt', async () => {
    const f = createFixture()
    const fresh = f.license({ lid: 'lic_old', iat: T0_SECONDS })
    f.respond({ status: 500, body: {} }, { status: 200, body: { license: fresh } })
    f.writeCached(f.license({ lid: 'lic_old', iat: T0_SECONDS - 604800 - 259200 - 10, expOffset: 0 }), 'lic_old')
    const ent = await f.client.ensureLicense(PACK)
    expect(ent.source).toBe('network')
    expect(f.calls.length).toBe(2)
  })

  it('rejects a license for another pack without writing it', async () => {
    const f = createFixture()
    const other = f.license({ lid: 'lic_other', pack: { id: 'com.other', version: '1.0.0', author_pub: 'A'.repeat(43) } })
    f.respond({ status: 200, body: { license: other } })
    f.writeCached(f.license({ iat: T0_SECONDS - 604800 - 259200 - 10, expOffset: 0 }))
    await expect(f.client.ensureLicense(PACK)).rejects.toMatchObject({ code: 'BAD_SERVER_LICENSE' })
    expect(existsSync(f.cachedPath('lic_other'))).toBe(false)
  })

  it('maps a SEAT_LIMIT rejection on activate to SERVER_REJECTED without writing a license', async () => {
    const f = createFixture()
    f.respond({ status: 409, body: { error: { code: 'SEAT_LIMIT', message: 'no seats' } } })
    await expect(f.client.activate(PACK, 'purchase-token')).rejects.toMatchObject({ code: 'SERVER_REJECTED' })
    expect(f.calls.length).toBe(1)
  })
})
