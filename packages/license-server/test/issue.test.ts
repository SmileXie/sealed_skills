import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad, openEntry, sealEntry } from '@sealed/pack-format'
import {
  b64u,
  rawPrivateBytes as rawPrivateBytesOf,
  rawPublicBytes as rawPublicBytesOf,
  unwrapEntryKey,
  verifyLicense,
  x25519PrivateFromRaw,
} from '@sealed/license-format'
import { ServerError, issueLicense, loadServerKeys, unwrapMaster, wrapMaster, type PackRecord } from '../src/index.js'

function testEnv() {
  const licenseKey = generateKeyPairSync('ed25519')
  const license = licenseKey.privateKey.export({ format: 'jwk' }) as { d: string }
  const proof = generateKeyPairSync('x25519')
  const proofRaw = proof.privateKey.export({ format: 'jwk' }) as { d: string }
  return {
    licenseKey,
    env: {
      SEALED_SERVER_LICENSE_KEY: license.d,
      SEALED_SERVER_PROOF_KEY: proofRaw.d,
      SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 9)),
    } as NodeJS.ProcessEnv,
  }
}

const pack: PackRecord = {
  packId: 'com.example.p', version: '1.0.0', label: '翻译', authorPub: 'A'.repeat(43),
  masterWrapped: '', trialEntries: ['meta'],
  entries: [{ id: 'meta', type: 'meta', size: 1 }, { id: 'skill:translate:body', type: 'text', size: 1 }, { id: 'data:x', type: 'data', size: 1 }],
}

describe('server keys and master wrapping', () => {
  it('loads keys from the environment and derives the proof public key', () => {
    const { env: e } = testEnv()
    const keys = loadServerKeys(e)
    expect(keys.masterWrapKey.length).toBe(32)
    expect(keys.proofPrivateKey.length).toBe(32)
    expect(keys.proofPublicB64).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('rejects a missing or malformed key', () => {
    expect(() => loadServerKeys({} as NodeJS.ProcessEnv)).toThrow(ServerError)
    const { env: e } = testEnv()
    let thrown: unknown
    try {
      loadServerKeys({ ...e, SEALED_SERVER_MASTER_KEY: 'nope' })
    } catch (err) {
      thrown = err
    }
    expect(thrown).toBeInstanceOf(ServerError)
    expect((thrown as ServerError).code).toBe('INTERNAL')
  })

  it('round-trips the master and detects tampering', () => {
    const key = Buffer.alloc(32, 3)
    const master = Buffer.alloc(32, 5)
    const wrapped = wrapMaster(master, key)
    expect(unwrapMaster(wrapped, key).equals(master)).toBe(true)
    const tampered = wrapped.slice(0, -2) + (wrapped.endsWith('AA') ? 'BB' : 'AA')
    expect(() => unwrapMaster(tampered, key)).toThrow(ServerError)
  })
})

describe('issueLicense', () => {
  it('issues a verifiable license bound to the device, the pack author key and the pack version', () => {
    const { licenseKey, env: e } = testEnv()
    const keys = loadServerKeys(e)
    const device = generateKeyPairSync('x25519')
    const devicePubB64 = b64u(rawPublicBytesOf(device.publicKey))
    const token = issueLicense({
      licenseId: 'lic_1', sub: 'cust', pack, devicePubB64, caps: ['full'], plan: 'pro', seatLimit: 2, now: 1_700_000_000,
    }, Buffer.alloc(32, 5), keys.licensePrivateKey)
    const payload = verifyLicense(token, [licenseKey.publicKey])
    expect(payload.lid).toBe('lic_1')
    expect(payload.dev).toBe(devicePubB64)
    expect(payload.pack).toEqual({ id: pack.packId, version: pack.version, author_pub: pack.authorPub })
    expect(payload.exp).toBe(1_700_000_000 + 604800)
    expect(payload.grace_until).toBe(1_700_000_000 + 604800 + 259200)
    expect(payload.keys.map((k) => k.eid).sort()).toEqual(['data:x', 'meta', 'skill:translate:body'])
  })

  it('grants only the entries the filter allows and unwraps to the real content key', () => {
    const { env: e } = testEnv()
    const keys = loadServerKeys(e)
    const device = generateKeyPairSync('x25519')
    const devicePubB64 = b64u(rawPublicBytesOf(device.publicKey))
    const master = Buffer.alloc(32, 7)
    const token = issueLicense({
      licenseId: 'lic_t', sub: 'trial', pack, devicePubB64, caps: ['trial'], plan: 'trial', seatLimit: 1, now: 100,
      entryFilter: (id) => id === 'meta',
    }, master, keys.licensePrivateKey)
    const payload = verifyLicense(token, [keys.licensePrivateKey])
    expect(payload.keys.map((k) => k.eid)).toEqual(['meta'])
    const ck = unwrapEntryKey(payload, 'meta', x25519PrivateFromRaw(rawPrivateBytesOf(device.privateKey)))
    expect(ck.equals(deriveEntryKey(master, pack.packId, pack.version, 'meta'))).toBe(true)
    const sealed = sealEntry(ck, entryAad(pack.packId, pack.version, 'meta'), Buffer.from('{skills:[]}'))
    expect(openEntry(ck, entryAad(pack.packId, pack.version, 'meta'), sealed.nonce, sealed.ct).toString('utf8')).toBe('{skills:[]}')
    expect(() => unwrapEntryKey(payload, 'data:x', x25519PrivateFromRaw(rawPrivateBytesOf(device.privateKey)))).toThrow('LICENSE_NO_GRANT')
  })
})
