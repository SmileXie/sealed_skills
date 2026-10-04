import { createPublicKey, diffieHellman, generateKeyPairSync, randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  rawPrivateBytes,
  rawPublicBytes,
  unwrapEntryKey,
  wrapEntryKey,
  x25519PrivateFromRaw,
  x25519PublicFromRaw,
} from '../src/index.js'
import type { LicensePayload } from '../src/index.js'

const device = generateKeyPairSync('x25519')
const foreign = generateKeyPairSync('x25519')

function payload(): LicensePayload {
  return {
    v: 1, lid: 'lic_9', sub: 'c', pack: { id: 'p', version: '1', author_pub: 'A' },
    dev: rawPublicBytes(device.publicKey).toString('base64url'),
    iat: 0, exp: 1, grace_until: 2, caps: ['full'], groups: [], keys: [], seats: { plan: 'pro', limit: 1 },
  }
}

describe('entry key wrapping', () => {
  it('round-trips a content key to the right device', () => {
    const p = payload()
    const ck = Buffer.alloc(32, 5)
    p.keys.push(wrapEntryKey(p, 'data:x', ck, device.publicKey))
    expect(unwrapEntryKey(p, 'data:x', device.privateKey).equals(ck)).toBe(true)
  })

  it('fails for a foreign device key', () => {
    const p = payload()
    p.keys.push(wrapEntryKey(p, 'data:x', Buffer.alloc(32, 5), device.publicKey))
    expect(() => unwrapEntryKey(p, 'data:x', foreign.privateKey)).toThrow('LICENSE_UNWRAP_FAILED')
  })

  it('reports a missing grant distinctly from a failed unwrap', () => {
    expect(() => unwrapEntryKey(payload(), 'data:y', device.privateKey)).toThrow('LICENSE_NO_GRANT')
  })

  it('rejects unwrapping an entry key with a mismatched payload lid', () => {
    const p = payload()
    p.keys.push(wrapEntryKey(p, 'data:x', Buffer.alloc(32, 5), device.publicKey))
    expect(() => unwrapEntryKey({ ...p, lid: 'lic_other' }, 'data:x', device.privateKey)).toThrow('LICENSE_UNWRAP_FAILED')
  })
})

describe('raw X25519 wire codec', () => {
  it('round-trips raw private key bytes', () => {
    const raw = randomBytes(32)
    expect(rawPrivateBytes(x25519PrivateFromRaw(raw)).equals(raw)).toBe(true)
  })

  it('interoperates a derived private key with the public codec', () => {
    const raw = randomBytes(32)
    const privateKey = x25519PrivateFromRaw(raw)
    const publicKey = createPublicKey(privateKey)
    const publicRaw = rawPublicBytes(publicKey)
    expect(rawPublicBytes(x25519PublicFromRaw(publicRaw)).equals(publicRaw)).toBe(true)

    const peer = generateKeyPairSync('x25519')
    const sharedFromPrivate = diffieHellman({ privateKey, publicKey: peer.publicKey })
    const sharedFromPeer = diffieHellman({ privateKey: peer.privateKey, publicKey: x25519PublicFromRaw(publicRaw) })
    expect(sharedFromPrivate.equals(sharedFromPeer)).toBe(true)
  })
})
