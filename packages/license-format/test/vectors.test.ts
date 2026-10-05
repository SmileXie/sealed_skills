import { createPrivateKey, createPublicKey } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  LicenseError,
  rawPublicBytes,
  signLicense,
  unwrapEntryKey,
  verifyLicense,
  wrapEntryKey,
  x25519PrivateFromRaw,
  x25519PublicFromRaw,
} from '../src/index.js'
import type { LicenseGrant, LicensePayload } from '../src/index.js'

/**
 * Golden-vector conformance for the PUBLIC license v1 format.
 *
 * The vectors are TEST-ONLY (fixed signing seed / device key / ephemeral key / nonce). Ed25519 in
 * Node is deterministic, so the full token is reproducible; the wrap is made reproducible via the
 * non-production `WrapEntryKeySeam`.
 */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

interface LicenseDoc {
  signing_seed_hex: string
  device_private_hex: string
  ephemeral_private_hex: string
  content_key_hex: string
  wrap_nonce_hex: string
  eid: string
  payload: LicensePayload
  expected_grant: LicenseGrant
  expected_token: string
}

const doc = JSON.parse(
  readFileSync(new URL('../../../test-vectors/license-format.json', import.meta.url), 'utf8'),
) as LicenseDoc

const signingKey = createPrivateKey({
  key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(doc.signing_seed_hex, 'hex')]),
  format: 'der',
  type: 'pkcs8',
})
const signingPublic = createPublicKey(signingKey)
const devicePrivate = x25519PrivateFromRaw(Buffer.from(doc.device_private_hex, 'hex'))
const devicePublic = x25519PublicFromRaw(rawPublicBytes(createPublicKey(devicePrivate)))
const ephemeralPrivate = x25519PrivateFromRaw(Buffer.from(doc.ephemeral_private_hex, 'hex'))
const contentKey = Buffer.from(doc.content_key_hex, 'hex')

describe('golden vectors: license-format', () => {
  it('reproduces the wrapped grant', () => {
    const grant = wrapEntryKey(doc.payload, doc.eid, contentKey, devicePublic, {
      ephemeralPrivateKey: ephemeralPrivate,
      nonce: Buffer.from(doc.wrap_nonce_hex, 'hex'),
    })
    expect(grant).toEqual(doc.expected_grant)
  })

  it('unwraps the grant back to the content key', () => {
    expect(unwrapEntryKey(doc.payload, doc.eid, devicePrivate).equals(contentKey)).toBe(true)
  })

  it('reproduces and verifies the signed token', () => {
    expect(signLicense(doc.payload, signingKey)).toBe(doc.expected_token)
    const verified = verifyLicense(doc.expected_token, [signingPublic])
    expect(verified).toEqual(doc.payload)
  })

  it('rejects a tampered signature', () => {
    const parsed = JSON.parse(doc.expected_token) as { payload: string; sig: string }
    const sig = Buffer.from(parsed.sig, 'base64url')
    sig[sig.length - 1] ^= 0x01
    const tampered = JSON.stringify({ payload: parsed.payload, sig: sig.toString('base64url') })
    expect(() => verifyLicense(tampered, [signingPublic])).toThrow(LicenseError)
  })

  it('rejects an untrusted signing key', () => {
    const other = createPublicKey(
      createPrivateKey({
        key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.alloc(32, 7)]),
        format: 'der',
        type: 'pkcs8',
      }),
    )
    expect(() => verifyLicense(doc.expected_token, [other])).toThrow(LicenseError)
  })
})