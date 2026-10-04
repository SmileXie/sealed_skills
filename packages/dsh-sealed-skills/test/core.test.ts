import { generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad, sealEntry, signManifest, writeContainer, type PackEntryMeta, type PackManifest } from '@sealed/pack-format'
import { signLicense, wrapEntryKey, type LicensePayload } from '@sealed/license-format'
import { SealedCore } from '../src/core.js'
import { FileKeystore, x25519PublicFromRaw } from '../src/keystore.js'

const author = generateKeyPairSync('ed25519')
const master = randomBytes(32)
const packId = 'com.example.translate'
const version = '1.0.0'

function ed25519RawX(key: KeyObject): string {
  return (key.export({ format: 'jwk' }) as { x: string }).x
}

function buildPack(entries: { id: string; type: PackEntryMeta['type']; body: string }[]): Buffer {
  const manifest: PackManifest = { pack_id: packId, version, label: '翻译', entry_count: entries.length, entries: [] }
  const chunks: { id: string; nonce: Buffer; ct: Buffer }[] = []
  for (const entry of entries) {
    const key = deriveEntryKey(master, packId, version, entry.id)
    const sealed = sealEntry(key, entryAad(packId, version, entry.id), Buffer.from(entry.body, 'utf8'))
    manifest.entries.push({ id: entry.id, type: entry.type, size: sealed.ct.length, trial: true })
    chunks.push({ id: entry.id, nonce: sealed.nonce, ct: sealed.ct })
  }
  const signature = signManifest(Buffer.from(JSON.stringify(manifest)), author.privateKey)
  return writeContainer({ manifest, chunks, signature })
}

const meta = JSON.stringify({
  skills: [{ name: 'translate', description: '翻译文本', whenToUse: '需要翻译时', invocation: { modelInvocable: true, userInvocable: true }, entries: ['skill:translate:body'] }],
  resources: {},
})
const pack = buildPack([
  { id: 'meta', type: 'meta', body: meta },
  { id: 'skill:translate:body', type: 'text', body: '把用户输入翻译成英文。\n' },
])

async function newKeystore(): Promise<FileKeystore> {
  const ks = new FileKeystore({ dir: mkdtempSync(join(tmpdir(), 'ks-')) })
  await ks.createDeviceKey()
  return ks
}

function licenseFor(devicePub: Buffer, entryIds: string[], overrides: Partial<LicensePayload> = {}): string {
  const payload: LicensePayload = {
    v: 1, lid: 'lic_t', sub: 'trial',
    pack: { id: packId, version, author_pub: ed25519RawX(author.publicKey) },
    dev: devicePub.toString('base64url'),
    iat: 0, exp: 4_000_000_000, grace_until: 4_000_000_000 + 3 * 86400,
    caps: ['trial'], groups: [], keys: [], seats: { plan: 'trial', limit: 1 },
    ...overrides,
  }
  for (const id of entryIds) {
    payload.keys.push(wrapEntryKey(payload, id, deriveEntryKey(master, packId, version, id), x25519PublicFromRaw(devicePub)))
  }
  return signLicense(payload, author.privateKey)
}

describe('SealedCore', () => {
  it('lists and reads a granted skill without exposing any file path', async () => {
    const ks = await newKeystore()
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    expect(await core.list()).toEqual([{ name: 'translate', description: '翻译文本', whenToUse: '需要翻译时', invocation: { modelInvocable: true, userInvocable: true } }])
    const skill = await core.readSkill('translate')
    expect(skill.content).toBe('把用户输入翻译成英文。\n')
    expect(skill).not.toHaveProperty('path')
    expect(await core.readEntry('skill:translate:body')).toBeInstanceOf(Buffer)
  })

  it('refuses an entry the license does not grant', async () => {
    const ks = await newKeystore()
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.readSkill('translate')).rejects.toMatchObject({ code: 'NOT_GRANTED' })
  })

  it('refuses an expired license before touching the pack', async () => {
    const ks = await newKeystore()
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body'], { exp: 100, grace_until: 200 }),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.list()).rejects.toMatchObject({ code: 'LICENSE_EXPIRED' })
  })

  it('stays usable inside the grace window', async () => {
    const ks = await newKeystore()
    const now = 150_000
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body'], { exp: 100, grace_until: 200 }),
      trustedLicenseKeys: [author.publicKey], keystore: ks, now: () => now,
    })
    expect((await core.readSkill('translate')).content).toContain('翻译')
  })

  it('rejects a pack signed by a different author key', async () => {
    const ks = await newKeystore()
    const other = generateKeyPairSync('ed25519')
    expect(() => new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(other.publicKey),
      license: licenseFor(Buffer.alloc(32, 1), ['meta']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })).toThrowError(expect.objectContaining({ code: 'PACK_SIGNATURE' }))
  })

  it('rejects a tampered chunk as a typed decrypt failure', async () => {
    const ks = await newKeystore()
    const tampered = Buffer.from(pack)
    const idx = tampered.length - 5
    tampered[idx] = tampered[idx] ^ 0xff
    const core = new SealedCore({
      pack: tampered, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.readSkill('translate')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' })
  })

  it('rejects an unknown skill name with META_INVALID', async () => {
    const ks = await newKeystore()
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.readSkill('nope')).rejects.toMatchObject({ code: 'META_INVALID' })
  })

  it('rejects a meta entry that is not valid JSON', async () => {
    const ks = await newKeystore()
    const badPack = buildPack([{ id: 'meta', type: 'meta', body: '{ not json' }])
    const core = new SealedCore({
      pack: badPack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.list()).rejects.toMatchObject({ code: 'META_INVALID' })
  })

  it('rejects a meta entry whose skills is not an array', async () => {
    const ks = await newKeystore()
    const badPack = buildPack([{ id: 'meta', type: 'meta', body: JSON.stringify({ skills: 'nope', resources: {} }) }])
    const core = new SealedCore({
      pack: badPack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.list()).rejects.toMatchObject({ code: 'META_INVALID' })
  })

  it('rejects a meta entry with a malformed skill element as META_INVALID, not a TypeError', async () => {
    const ks = await newKeystore()
    const body = JSON.stringify({ skills: [{ name: 'translate', description: 'd', invocation: { modelInvocable: true, userInvocable: true } }], resources: {} })
    const badPack = buildPack([{ id: 'meta', type: 'meta', body }])
    const core = new SealedCore({
      pack: badPack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.list()).rejects.toMatchObject({ code: 'META_INVALID' })
    await expect(core.readSkill('translate')).rejects.toMatchObject({ code: 'META_INVALID' })
  })

  it('rejects a null skill element as META_INVALID, not a TypeError', async () => {
    const ks = await newKeystore()
    const badPack = buildPack([{ id: 'meta', type: 'meta', body: JSON.stringify({ skills: [null], resources: {} }) }])
    const core = new SealedCore({
      pack: badPack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.list()).rejects.toMatchObject({ code: 'META_INVALID' })
  })

  it('reports a corrupt device keystore as LICENSE_INVALID', async () => {
    const ks = await newKeystore()
    const license = licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body'])
    writeFileSync(join(ks.dir, 'device.json'), '{ not json', 'utf8')
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license, trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.readSkill('translate')).rejects.toMatchObject({ code: 'LICENSE_INVALID' })
  })
})
