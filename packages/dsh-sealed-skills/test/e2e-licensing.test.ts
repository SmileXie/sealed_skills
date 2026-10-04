import { createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
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
import { SealedCore } from '../src/core.js'
import { LicenseClient } from '../src/license-client.js'
import { FileKeystore } from '../src/keystore.js'
import { apply, type SkillsContext } from '../src/plugin.js'
import { parsePlaceholder } from '../src/session-events.js'
import type { DshSkillCandidate, DshSkillProvider, DshSkillProviderControl } from '../src/provider.js'

const packId = 'com.example.translate'
const version = '1.0.0'
const ADMIN = 'admin-token'
const packRef = { id: packId, version }
const master = randomBytes(32)
const author = generateKeyPairSync('ed25519')
const authorPub = (author.publicKey.export({ format: 'jwk' }) as { x: string }).x

// A minimal sealed pack whose body entry is withheld from the trial set.
function buildPack(id = packId, ver = version): { file: Buffer; manifest: PackManifest } {
  const entries: { id: string; type: PackEntryMeta['type']; body: string }[] = [
    {
      id: 'meta',
      type: 'meta',
      body: JSON.stringify({
        skills: [{
          name: 'translate', description: '翻译',
          invocation: { modelInvocable: true, userInvocable: true },
          entries: ['skill:translate:body'],
        }],
        resources: {},
      }),
    },
    { id: 'skill:translate:body', type: 'text', body: '把用户输入翻译成英文。\n' },
  ]
  const manifest: PackManifest = { pack_id: id, version: ver, label: '翻译', entry_count: entries.length, entries: [] }
  const chunks = entries.map((entry) => {
    const key = deriveEntryKey(master, id, ver, entry.id)
    const sealed = sealEntry(key, entryAad(id, ver, entry.id), Buffer.from(entry.body, 'utf8'))
    manifest.entries.push({ id: entry.id, type: entry.type, size: sealed.ct.length, trial: entry.id !== 'skill:translate:body' })
    return { id: entry.id, nonce: sealed.nonce, ct: sealed.ct }
  })
  const signature = signManifest(encodeManifest(manifest), author.privateKey)
  return { file: writeContainer({ manifest, chunks, signature }), manifest }
}

function publishBody(manifest: PackManifest) {
  return {
    pack: packRef,
    author_pub: authorPub,
    label: '翻译',
    master_b64: master.toString('base64url'),
    trial_entries: manifest.entries.filter((entry) => entry.trial).map((entry) => entry.id),
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

async function publish(url: string, manifest: PackManifest): Promise<void> {
  const response = await fetch(url + '/v1/admin/packs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN },
    body: JSON.stringify(publishBody(manifest)),
  })
  expect(response.status).toBe(200)
}

async function newClient(url: string, serverProofPubB64: string, licensePubB64: string, homeDir: string): Promise<LicenseClient> {
  const keystore = new FileKeystore({ dir: homeDir })
  await keystore.createDeviceKey()
  const trustedLicenseKeys = [createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: licensePubB64 }, format: 'jwk' })]
  return new LicenseClient({
    serverUrl: url, serverProofPubB64, keystore, homeDir, trustedLicenseKeys,
    retry: { attempts: 2, baseMs: 1, maxMs: 2 },
  })
}

function trustedKeys(licensePubB64: string) {
  return [createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: licensePubB64 }, format: 'jwk' })]
}

function fakeContext(): { ctx: SkillsContext; provider: () => DshSkillProvider } {
  let registered: DshSkillProvider | undefined
  const ctx: SkillsContext = {
    skills: {
      registerProvider(create: (control: DshSkillProviderControl) => DshSkillProvider) {
        registered = create({ signal: new AbortController().signal, invalidate: () => {} })
        return () => {}
      },
    },
  }
  const readyCtx: SkillsContext = {
    ...ctx,
    logger: { warn: () => {} },
    sessions: { registerMessageProjection: () => async () => {} },
    on: () => () => {},
  }
  return { ctx: readyCtx, provider: () => registered! }
}

describe('M2 licensing end to end', () => {
  it('publishes, activates, decrypts, renews and then fails to renew after a revoke', async () => {
    const { url, store, keys, licensePublic } = await startServer()
    const { file: pack, manifest } = buildPack()
    await publish(url, manifest)
    store.putPurchase({ token: 'purchase-1', sub: 'cust', packId, version, plan: 'pro', seats: 1 })

    const home = mkdtempSync(join(tmpdir(), 'sealed-home-'))
    const client = await newClient(url, keys.proofPublicB64, licensePublic, home)
    const entitlement = await client.activate(packRef, 'purchase-1')
    expect(entitlement.state).toBe('active')
    expect(entitlement.payload.caps).toEqual(['full'])

    const core = new SealedCore({
      pack, license: entitlement.license, keystore: new FileKeystore({ dir: home }),
      trustedLicenseKeys: trustedKeys(licensePublic),
    })
    expect((await core.list()).map((skill) => skill.name)).toEqual(['translate'])
    expect((await core.readSkill('translate')).content).toBe('把用户输入翻译成英文。\n')

    const renewed = await client.renew(packRef, entitlement.license)
    expect(renewed.source).toBe('network')

    const revoked = await fetch(url + '/v1/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN },
      body: JSON.stringify({ license_id: entitlement.payload.lid }),
    })
    expect((await revoked.json() as { revoked: number }).revoked).toBe(1)
    await expect(client.renew(packRef, renewed.license)).rejects.toMatchObject({ code: 'LICENSE_REVOKED' })
  })

  it('grants a server trial only the trial entries and refuses the rest', async () => {
    const { url, store, keys, licensePublic } = await startServer()
    const { file: pack, manifest } = buildPack()
    await publish(url, manifest)

    const home = mkdtempSync(join(tmpdir(), 'sealed-home-'))
    const client = await newClient(url, keys.proofPublicB64, licensePublic, home)
    const trial = await client.activateTrial(packRef)
    expect(trial.payload.caps).toEqual(['trial'])

    const core = new SealedCore({
      pack, license: trial.license, keystore: new FileKeystore({ dir: home }),
      trustedLicenseKeys: trustedKeys(licensePublic),
    })
    await expect(core.readSkill('translate')).rejects.toMatchObject({ code: 'NOT_GRANTED' })

    const devicePub = (await new FileKeystore({ dir: home }).loadDevicePublicKey())!.toString('base64url')
    expect(store.getTrial(devicePub, packId, version)).toBeDefined()
  })

  it('activates and decrypts through the real plugin on a fresh machine (no pre-created device key)', async () => {
    const { url, store, keys, licensePublic } = await startServer()
    const { file: pack, manifest } = buildPack()
    await publish(url, manifest)
    store.putPurchase({ token: 'purchase-fresh', sub: 'cust', packId, version, plan: 'pro', seats: 1 })

    const home = mkdtempSync(join(tmpdir(), 'sealed-home-'))
    const packPath = join(home, 'translate.sealedpack')
    writeFileSync(packPath, pack)
    // 全新机器：没有预置设备密钥，插件必须自行生成（规范 §7.2 步骤 1）。
    expect(existsSync(join(home, 'device.json'))).toBe(false)

    const { ctx, provider } = fakeContext()
    apply(ctx, {
      mounts: [{ packPath, purchaseToken: 'purchase-fresh' }],
      trustedLicenseKeysB64: [licensePublic],
      serverUrl: url,
      serverProofPubB64: keys.proofPublicB64,
      keystoreDir: home,
      registerSessionEventType: () => {},
    })

    const candidates = (await provider().list({})) as DshSkillCandidate[]
    expect(candidates.map((candidate) => candidate.name)).toEqual(['translate'])
    const definition = await provider().get(candidates[0], {})
    const placeholder = definition?.content ?? ''
    expect(parsePlaceholder(placeholder)).toHaveLength(1)
    expect(placeholder).not.toContain('把用户输入翻译成英文。\n')
    expect(existsSync(join(home, 'device.json'))).toBe(true)
  })

  it('keeps a healthy mount available when a sibling mount is denied', async () => {
    const { url, store, keys, licensePublic } = await startServer()
    const healthy = buildPack()
    await publish(url, healthy.manifest)
    store.putPurchase({ token: 'purchase-mix', sub: 'cust', packId, version, plan: 'pro', seats: 1 })

    const denied = buildPack('com.example.denied', '1.0.0')
    const home = mkdtempSync(join(tmpdir(), 'sealed-home-'))
    const healthyPath = join(home, 'healthy.sealedpack')
    const deniedPath = join(home, 'denied.sealedpack')
    writeFileSync(healthyPath, healthy.file)
    writeFileSync(deniedPath, denied.file)

    const { ctx, provider } = fakeContext()
    apply(ctx, {
      mounts: [
        { packPath: deniedPath }, // 无 offline license / purchaseToken / trial → NO_LICENSE，被跳过
        { packPath: healthyPath, purchaseToken: 'purchase-mix' },
      ],
      trustedLicenseKeysB64: [licensePublic],
      serverUrl: url,
      serverProofPubB64: keys.proofPublicB64,
      keystoreDir: home,
      registerSessionEventType: () => {},
    })

    const candidates = (await provider().list({})) as DshSkillCandidate[]
    expect(candidates.map((candidate) => candidate.name)).toEqual(['translate'])
    const loaded = (await provider().get(candidates[0], {}))?.content ?? ''
    expect(parsePlaceholder(loaded)).toHaveLength(1)
    expect(loaded).not.toContain('把用户输入翻译成英文。\n')
  })

  it('rebuilds a cached mount after the refresh interval elapses', async () => {
    const { url, store, keys, licensePublic } = await startServer()
    const { file: pack, manifest } = buildPack()
    await publish(url, manifest)
    store.putPurchase({ token: 'purchase-refresh', sub: 'cust', packId, version, plan: 'pro', seats: 1 })

    const home = mkdtempSync(join(tmpdir(), 'sealed-home-'))
    const packPath = join(home, 'translate.sealedpack')
    writeFileSync(packPath, pack)

    // 通过一个独立 client 拿到一份离线 license，再以 licensePath 挂载。
    const issued = await newClient(url, keys.proofPublicB64, licensePublic, home)
    const entitlement = await issued.activate(packRef, 'purchase-refresh')
    const licensePath = join(home, 'offline.license.json')
    writeFileSync(licensePath, entitlement.license)

    const clock = { t: Date.now() }
    const { ctx, provider } = fakeContext()
    apply(ctx, {
      mounts: [{ packPath, licensePath }],
      trustedLicenseKeysB64: [licensePublic],
      keystoreDir: home,
      registerSessionEventType: () => {},
      now: () => clock.t,
    })

    expect((await provider().list({}) as DshSkillCandidate[]).map((c) => c.name)).toEqual(['translate'])

    // 缓存仍在：删掉离线 license 文件后，未到刷新窗口前依然可用。
    rmSync(licensePath, { force: true })
    expect((await provider().list({}) as DshSkillCandidate[]).map((c) => c.name)).toEqual(['translate'])

    // 越过 24h 刷新窗口：本次访问丢弃缓存并重建，重新读取已删除的 licensePath 失败 → 挂载停用。
    clock.t += 24 * 60 * 60 * 1000 + 1
    expect(await provider().list({})).toEqual([])
  })
})
