import { diffieHellman, generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  b64u, deviceProofKey, deviceProofMac, deviceProofMessage, rawPrivateBytes, rawPublicBytes,
  unb64u, x25519PublicFromRaw,
} from '@sealed/license-format'
import {
  handleRenew, handleRevoke, issueLicense, loadServerKeys, openStore, wrapMaster,
  type PackRecord, type ServerKeys, type Store,
} from '../src/index.js'

const MASTER = Buffer.alloc(32, 7)

function fixture() {
  const licenseKey = generateKeyPairSync('ed25519')
  const proofKey = generateKeyPairSync('x25519')
  const keys = loadServerKeys({
    SEALED_SERVER_LICENSE_KEY: (licenseKey.privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proofKey.privateKey).toString('base64url'),
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 5)),
  } as NodeJS.ProcessEnv)
  const store = openStore(':memory:')
  const pack: PackRecord = {
    packId: 'com.example.p', version: '1.0.0', label: 'p', authorPub: 'A'.repeat(43),
    masterWrapped: wrapMaster(MASTER, keys.masterWrapKey), trialEntries: [],
    entries: [{ id: 'meta', type: 'meta', size: 1 }],
  }
  store.putPack(pack)
  const device = generateKeyPairSync('x25519')
  const devicePub = rawPublicBytes(device.publicKey).toString('base64url')
  const license = issueLicense({
    licenseId: 'lic_full_1', sub: 'cust', pack, devicePubB64: devicePub,
    caps: ['full'], plan: 'pro', seatLimit: 2, now: 1000,
  }, MASTER, keys.licensePrivateKey)
  store.putLicense({
    licenseId: 'lic_full_1', sub: 'cust', packId: pack.packId, version: pack.version,
    devicePub, caps: ['full'], plan: 'pro', seatLimit: 2, iat: 1000, exp: 1000 + 604800,
    graceUntil: 1000 + 604800 + 259200, revoked: false,
  })
  return { store, keys, pack, device, devicePub, license }
}

function proof(keys: ServerKeys, device: ReturnType<typeof generateKeyPairSync>['privateKey'], lid: string, nonce: string, ts: number): string {
  const shared = diffieHellman({ privateKey: device, publicKey: x25519PublicFromRaw(unb64u(keys.proofPublicB64)) })
  return deviceProofMac(deviceProofKey(shared, lid), deviceProofMessage(lid, nonce, ts))
}

describe('handleRenew', () => {
  it('re-issues for a fresh nonce inside the skew window', () => {
    const f = fixture()
    const mac = proof(f.keys, f.device.privateKey, 'lic_full_1', 'n1', 1001)
    const result = handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n1', ts: 1001, mac }, 1001)
    expect(result.status).toBe(200)
    expect(typeof (result.body as { license: string }).license).toBe('string')
    expect(f.store.getLicense('lic_full_1')?.iat).toBe(1001)
    expect(f.store.listAudit().at(-1)?.action).toBe('renew')
  })

  it('rejects a replayed nonce and an out-of-window timestamp', () => {
    const f = fixture()
    const mac = proof(f.keys, f.device.privateKey, 'lic_full_1', 'n1', 1001)
    handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n1', ts: 1001, mac }, 1001)
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n1', ts: 1001, mac }, 1001))
      .toThrowError(expect.objectContaining({ code: 'REPLAY' }))
    const stale = proof(f.keys, f.device.privateKey, 'lic_full_1', 'n2', 1)
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n2', ts: 1, mac: stale }, 1001))
      .toThrowError(expect.objectContaining({ code: 'BAD_REQUEST' }))
  })

  it('rejects a bad device proof, an unknown license and a revoked license', () => {
    const f = fixture()
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n', ts: 1001, mac: 'AAAA' }, 1001))
      .toThrowError(expect.objectContaining({ code: 'BAD_DEVICE_PROOF' }))
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_nope', device_pub: f.devicePub, nonce: 'n', ts: 1001, mac: 'AAAA' }, 1001))
      .toThrowError(expect.objectContaining({ code: 'UNKNOWN_LICENSE' }))
    f.store.markRevoked('lic_full_1')
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n', ts: 1001, mac: 'AAAA' }, 1001))
      .toThrowError(expect.objectContaining({ code: 'REVOKED' }))
  })
})

describe('handleRevoke', () => {
  it('revokes by license id, releases the seat and audits the action', () => {
    const f = fixture()
    f.store.putSeat({ sub: 'cust', packId: f.pack.packId, version: f.pack.version, devicePub: f.devicePub, licenseId: 'lic_full_1' })
    expect(handleRevoke(f.store, { license_id: 'lic_full_1' }, 2000)).toEqual({ status: 200, body: { revoked: 1 } })
    expect(f.store.getLicense('lic_full_1')?.revoked).toBe(true)
    expect(f.store.countSeats('cust', f.pack.packId, f.pack.version)).toBe(0)
    expect(f.store.listAudit().at(-1)).toMatchObject({ action: 'revoke', actor: 'admin' })
  })

  it('is idempotent and 404s when nothing matches', () => {
    const f = fixture()
    handleRevoke(f.store, { license_id: 'lic_full_1' }, 2000)
    expect(handleRevoke(f.store, { license_id: 'lic_full_1' }, 2001)).toEqual({ status: 200, body: { revoked: 0 } })
    expect(() => handleRevoke(f.store, { license_id: 'lic_nope' }, 2002))
      .toThrowError(expect.objectContaining({ status: 404, code: 'UNKNOWN_LICENSE' }))
  })
})
