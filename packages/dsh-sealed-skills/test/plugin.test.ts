import { createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto'
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  deriveEntryKey, encodeManifest, entryAad, sealEntry, signManifest, writeContainer,
  type PackEntryMeta, type PackManifest,
} from '@sealed/pack-format'
import { b64u, rawPrivateBytes } from '@sealed/license-format'
import { createApp, loadServerKeys, openStore, serverLicensePublicB64 } from '@sealed/license-server'
import { apply, inject, name, type SkillsContext } from '../src/plugin.js'
import { parsePlaceholder } from '../src/session-events.js'
import type { DshSkillCandidate, DshSkillProvider, DshSkillProviderControl } from '../src/provider.js'

function fakeContext(overrides: Partial<SkillsContext> = {}): { ctx: SkillsContext; provider: () => DshSkillProvider } {
  let registered: DshSkillProvider | undefined
  const ctx: SkillsContext = {
    skills: {
      registerProvider(create: (control: DshSkillProviderControl) => DshSkillProvider) {
        registered = create({ signal: new AbortController().signal, invalidate: () => {} })
        return () => {}
      },
    },
    logger: { warn: () => {} },
    ...overrides,
  }
  return { ctx, provider: () => registered! }
}

function freshKeystoreDir(): string {
  return mkdtempSync(join(tmpdir(), 'sealed-plugin-'))
}

// --- Real mounted-pack fixture (mirrors test/e2e-licensing.test.ts) -----------------------------
// A pack that really decrypts is what makes the fail-closed assertions DISCRIMINATING: with
// `mounts: []` the provider returns []/undefined no matter whether the readiness gate exists.

const packId = 'com.example.gate'
const version = '1.0.0'
const ADMIN = 'admin-token'
const packRef = { id: packId, version }
const BODY = 'PLAINTEXT-BODY-MUST-NOT-LEAK'
const master = randomBytes(32)
const author = generateKeyPairSync('ed25519')
const authorPub = (author.publicKey.export({ format: 'jwk' }) as { x: string }).x

function buildPack(): { file: Buffer; manifest: PackManifest } {
  const entries: { id: string; type: PackEntryMeta['type']; body: string }[] = [
    {
      id: 'meta',
      type: 'meta',
      body: JSON.stringify({
        skills: [{
          name: 'translate', description: 'gate fixture',
          invocation: { modelInvocable: true, userInvocable: true },
          entries: ['skill:translate:body'],
        }],
        resources: {},
      }),
    },
    { id: 'skill:translate:body', type: 'text', body: BODY },
  ]
  const manifest: PackManifest = { pack_id: packId, version, label: 'gate', entry_count: entries.length, entries: [] }
  const chunks = entries.map((entry) => {
    const key = deriveEntryKey(master, packId, version, entry.id)
    const sealed = sealEntry(key, entryAad(packId, version, entry.id), Buffer.from(entry.body, 'utf8'))
    manifest.entries.push({ id: entry.id, type: entry.type, size: sealed.ct.length, trial: false })
    return { id: entry.id, nonce: sealed.nonce, ct: sealed.ct }
  })
  const signature = signManifest(encodeManifest(manifest), author.privateKey)
  return { file: writeContainer({ manifest, chunks, signature }), manifest }
}

function publishBody(manifest: PackManifest) {
  return {
    pack: packRef, author_pub: authorPub, label: 'gate',
    master_b64: master.toString('base64url'),
    trial_entries: [] as string[],
    entries: manifest.entries.map((entry) => ({ id: entry.id, type: entry.type, size: entry.size })),
  }
}

let current: { close: () => void } | undefined
afterEach(() => { current?.close(); current = undefined })

async function startServer() {
  const proofKey = generateKeyPairSync('x25519')
  const keys = loadServerKeys({
    SEALED_SERVER_LICENSE_KEY: (generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proofKey.privateKey).toString('base64url'),
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 4)),
  } as NodeJS.ProcessEnv)
  const store = openStore(':memory:')
  const server = createApp({ store, keys, adminToken: ADMIN })
  server.listen(0)
  current = server
  await new Promise<void>((resolve) => server.once('listening', () => resolve()))
  const url = 'http://127.0.0.1:' + (server.address() as AddressInfo).port
  return { url, store, keys, licensePublic: serverLicensePublicB64(keys) }
}

interface GateFixture {
  readonly url: string
  readonly proofPublicB64: string
  readonly licensePublic: string
  readonly home: string
  readonly packPath: string
}

async function mountRealPack(): Promise<GateFixture> {
  const { url, store, keys, licensePublic } = await startServer()
  const { file: pack, manifest } = buildPack()
  const published = await fetch(url + '/v1/admin/packs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN },
    body: JSON.stringify(publishBody(manifest)),
  })
  expect(published.status).toBe(200)
  store.putPurchase({ token: 'purchase-gate', sub: 'cust', packId, version, plan: 'pro', seats: 1 })
  const home = mkdtempSync(join(tmpdir(), 'sealed-gate-'))
  const packPath = join(home, 'translate.sealedpack')
  writeFileSync(packPath, pack)
  return { url, proofPublicB64: keys.proofPublicB64, licensePublic, home, packPath }
}

function mountConfig(fixture: GateFixture) {
  return {
    mounts: [{ packPath: fixture.packPath, purchaseToken: 'purchase-gate' }],
    trustedLicenseKeysB64: [fixture.licensePublic],
    serverUrl: fixture.url,
    serverProofPubB64: fixture.proofPublicB64,
    keystoreDir: fixture.home,
  }
}

describe('sealed-skills plugin', () => {
  it('declares the dsh plugin metadata', () => {
    expect(name).toBe('sealed-skills')
    expect(inject).toContain('skills')
  })

  it('registers a sealed provider on ctx.skills synchronously during apply', () => {
    const { ctx, provider } = fakeContext()
    apply(ctx, { mounts: [], trustedLicenseKeysB64: [], keystoreDir: freshKeystoreDir() })
    expect(provider().name).toBe('sealed')
  })

  it('reports no candidates when nothing is mounted', async () => {
    const { ctx, provider } = fakeContext()
    apply(ctx, { mounts: [], trustedLicenseKeysB64: [], keystoreDir: freshKeystoreDir() })
    expect(await provider().list({})).toEqual([])
  })

  it('returns the dsh effect disposer from apply', () => {
    const { ctx } = fakeContext()
    const dispose = apply(ctx, { mounts: [], trustedLicenseKeysB64: [], keystoreDir: freshKeystoreDir() })
    expect(typeof dispose).toBe('function')
    expect(() => dispose()).not.toThrow()
  })

  it('skips a mount whose pack file is missing instead of rejecting list()', async () => {
    const dir = freshKeystoreDir()
    const { ctx, provider } = fakeContext()
    apply(ctx, {
      mounts: [{ packPath: join(dir, 'missing.sealedpack'), licensePath: join(dir, 'missing.license') }],
      trustedLicenseKeysB64: [], keystoreDir: freshKeystoreDir(),
    })
    await expect(provider().list({})).resolves.toEqual([])
  })

  it('skips a corrupt mount instead of rejecting list()', async () => {
    const dir = freshKeystoreDir()
    const packPath = join(dir, 'corrupt.sealedpack')
    const licensePath = join(dir, 'corrupt.license')
    writeFileSync(packPath, 'not a sealed pack')
    writeFileSync(licensePath, '{}')
    const { ctx, provider } = fakeContext()
    apply(ctx, {
      mounts: [{ packPath, licensePath }],
      trustedLicenseKeysB64: [], keystoreDir: freshKeystoreDir(),
    })
    await expect(provider().list({})).resolves.toEqual([])
    await expect(provider().get({ name: 'x', locator: { sealedSkill: 'x' } } as never, {})).resolves.toBeUndefined()
  })
})

describe('sealed-skills plugin log-mask fail-closed', () => {
  const lookup = { name: 'translate', locator: { sealedSkill: 'translate' } } as never

  it('withholds a real mounted body when the projection cannot be registered', async () => {
    const fixture = await mountRealPack()
    const { ctx, provider } = fakeContext({
      sessions: {
        registerMessageProjection: () => {
          throw new Error('session message projection sealed/redacted is already registered')
        },
      },
      on: () => () => {},
    })
    apply(ctx, { ...mountConfig(fixture), registerSessionEventType: () => {} })
    // The same pack IS served by the ready-path test below, so `[]`/`undefined` here can only come
    // from the readiness gate. Delete the gate and this list() would surface `translate`.
    await expect(provider().list({})).resolves.toEqual([])
    await expect(provider().get(lookup, {})).resolves.toBeUndefined()
  })

  it('withholds a real mounted body when the marker event type cannot be registered', async () => {
    const fixture = await mountRealPack()
    const { ctx, provider } = fakeContext({
      sessions: { registerMessageProjection: () => async () => {} },
      on: () => () => {},
    })
    apply(ctx, {
      ...mountConfig(fixture),
      registerSessionEventType: () => { throw new Error('the harness event catalog is unavailable') },
    })
    await expect(provider().list({})).resolves.toEqual([])
    await expect(provider().get(lookup, {})).resolves.toBeUndefined()
  })

  it('withholds a real mounted body when the context cannot observe session events', async () => {
    const fixture = await mountRealPack()
    const { ctx, provider } = fakeContext({
      sessions: { registerMessageProjection: () => async () => {} },
    })
    apply(ctx, { ...mountConfig(fixture), registerSessionEventType: () => {} })
    await expect(provider().list({})).resolves.toEqual([])
    await expect(provider().get(lookup, {})).resolves.toBeUndefined()
  })

  it('serves only the placeholder for a real mounted pack once the log-mask is ready', async () => {
    const fixture = await mountRealPack()
    const { ctx, provider } = fakeContext({
      sessions: { registerMessageProjection: () => async () => {} },
      on: () => () => {},
    })
    apply(ctx, { ...mountConfig(fixture), registerSessionEventType: () => {} })

    const candidates = (await provider().list({})) as DshSkillCandidate[]
    expect(candidates.map((candidate) => candidate.name)).toEqual(['translate'])

    const definition = await provider().get(candidates[0], {})
    const content = definition?.content ?? ''
    const tokens = parsePlaceholder(content)
    expect(tokens).toHaveLength(1)
    expect(tokens[0]).toMatch(/^[A-Za-z0-9_-]{22}$/)
    expect(content).not.toContain(BODY)
    expect(existsSync(join(fixture.home, 'device.json'))).toBe(true)
  })
})
