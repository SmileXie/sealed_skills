import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { licenseStatus, parseLicense, signLicense, verifyLicense } from '../src/index.js'
import type { LicensePayload } from '../src/index.js'

const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const { publicKey: otherPublic } = generateKeyPairSync('ed25519')

function sample(overrides: Partial<LicensePayload> = {}): LicensePayload {
  return {
    v: 1, lid: 'lic_1', sub: 'cust_1',
    pack: { id: 'com.example.p', version: '1.0.0', author_pub: 'AAAA' },
    dev: 'BBBB', iat: 1000, exp: 2000, grace_until: 3000,
    caps: ['trial'], groups: ['g1'],
    keys: [{ eid: 'meta', eph: 'CCCC', n: 'DDDD', c: 'EEEE' }],
    seats: { plan: 'pro', limit: 1 },
    ...overrides,
  }
}

describe('license token', () => {
  it('signs and verifies, preserving the payload', () => {
    expect(verifyLicense(signLicense(sample(), privateKey), [publicKey])).toEqual(sample())
  })

  it('rejects a token signed by another key', () => {
    expect(() => verifyLicense(signLicense(sample(), privateKey), [otherPublic])).toThrow('LICENSE_BAD_SIGNATURE')
  })

  it('rejects a tampered payload', () => {
    const token = JSON.parse(signLicense(sample(), privateKey)) as { payload: string; sig: string }
    const payload = JSON.parse(Buffer.from(token.payload, 'base64url').toString('utf8')) as LicensePayload
    payload.exp = 999999
    const forged = JSON.stringify({ payload: Buffer.from(JSON.stringify(payload)).toString('base64url'), sig: token.sig })
    expect(() => verifyLicense(forged, [publicKey])).toThrow('LICENSE_BAD_SIGNATURE')
  })

  it('reports active, grace and expired around the boundaries', () => {
    const p = sample()
    expect(licenseStatus(p, 1999_000)).toBe('active')
    expect(licenseStatus(p, 2000_000)).toBe('grace')
    expect(licenseStatus(p, 2999_000)).toBe('grace')
    expect(licenseStatus(p, 3000_000)).toBe('expired')
  })

  it('rejects structurally invalid payloads', () => {
    expect(() => parseLicense('{"payload":"e30","sig":"AA"}')).toThrow('LICENSE_MALFORMED')
  })
})
