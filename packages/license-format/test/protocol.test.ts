import { diffieHellman, generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  deviceProofKey, deviceProofMac, deviceProofMessage, isRawX25519Pub,
  parseErrorEnvelope, validateActivateRequest, validateRenewRequest, validateTrialRequest,
  validateRevokeRequest, rawPublicBytes, x25519PrivateFromRaw, x25519PublicFromRaw, ProtocolRequestError,
} from '../src/index.js'

describe('protocol validators', () => {
  it('accepts a well-formed trial request and rejects junk', () => {
    const ok = { device_pub: 'A'.repeat(43), pack: { id: 'com.example.p', version: '1.0.0' } }
    expect(validateTrialRequest(ok)).toEqual(ok)
    expect(() => validateTrialRequest(null)).toThrow(ProtocolRequestError)
    expect(() => validateTrialRequest({ ...ok, device_pub: 'short' })).toThrow('BAD_REQUEST')
    expect(() => validateTrialRequest({ ...ok, pack: { id: '', version: '1.0.0' } })).toThrow('BAD_REQUEST')
    expect(() => validateTrialRequest({ ...ok, extra: 1 })).not.toThrow()
  })

  it('accepts an activate request and a renew request', () => {
    expect(validateActivateRequest({ device_pub: 'A'.repeat(43), purchase_token: 't', pack: { id: 'p', version: '1' } }).purchase_token).toBe('t')
    const renew = { license_id: 'lic_1', device_pub: 'A'.repeat(43), nonce: 'n', ts: 1_700_000_000, mac: 'm' }
    expect(validateRenewRequest(renew)).toEqual(renew)
    expect(() => validateRenewRequest({ ...renew, ts: 'now' })).toThrow('BAD_REQUEST')
  })
})

describe('device proof (DH-MAC)', () => {
  it('both sides derive the same key and the server-side mac matches', () => {
    const device = generateKeyPairSync('x25519')
    const server = generateKeyPairSync('x25519')
    const devicePub = rawPublicBytes(device.publicKey)
    const clientShared = diffieHellman({ privateKey: device.privateKey, publicKey: server.publicKey })
    const serverShared = diffieHellman({ privateKey: server.privateKey, publicKey: x25519PublicFromRaw(devicePub) })
    const msg = deviceProofMessage('lic_1', 'nonce-1', 1_700_000_000)
    const clientMac = deviceProofMac(deviceProofKey(clientShared, 'lic_1'), msg)
    const serverMac = deviceProofMac(deviceProofKey(serverShared, 'lic_1'), msg)
    expect(clientMac).toBe(serverMac)
    expect(clientMac).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('a different license id or nonce yields a different mac', () => {
    const key = Buffer.alloc(32, 7)
    expect(deviceProofMac(key, deviceProofMessage('a', 'n', 1))).not.toBe(deviceProofMac(key, deviceProofMessage('b', 'n', 1)))
    expect(deviceProofMac(key, deviceProofMessage('a', 'n', 1))).not.toBe(deviceProofMac(key, deviceProofMessage('a', 'm', 1)))
  })
})

describe('helpers', () => {
  it('recognises raw 32-byte base64url keys and error envelopes', () => {
    expect(isRawX25519Pub('A'.repeat(43))).toBe(true)
    expect(isRawX25519Pub('A'.repeat(42))).toBe(false)
    expect(parseErrorEnvelope({ error: { code: 'REPLAY', message: 'x' } })).toEqual({ code: 'REPLAY', message: 'x' })
    expect(parseErrorEnvelope({ error: { code: 'NOPE' } })).toBeUndefined()
    expect(parseErrorEnvelope('boom')).toBeUndefined()
  })
})

describe('validateRevokeRequest', () => {
  it('accepts each identifier and rejects an empty request', () => {
    expect(validateRevokeRequest({ license_id: 'lic_x' })).toEqual({ license_id: 'lic_x' })
    expect(validateRevokeRequest({ device_pub: 'A'.repeat(43) })).toEqual({ device_pub: 'A'.repeat(43) })
    expect(validateRevokeRequest({ seat: 'lic_y' })).toEqual({ seat: 'lic_y' })
    expect(() => validateRevokeRequest({})).toThrowError(/at least one/)
    expect(() => validateRevokeRequest({ license_id: 7 })).toThrowError(/license_id/)
  })
})
