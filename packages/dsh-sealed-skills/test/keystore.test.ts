import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { FileKeystore, KeystoreError, x25519PrivateFromRaw } from '../src/keystore.js'

function fresh(): FileKeystore {
  return new FileKeystore({ dir: mkdtempSync(join(tmpdir(), 'sealed-')) })
}

describe('FileKeystore', () => {
  it('creates a 32-byte device key pair on demand', async () => {
    const ks = fresh()
    expect(await ks.loadDevicePublicKey()).toBeUndefined()
    await ks.createDeviceKey()
    const priv = await ks.loadDevicePrivateKey()
    const pub = await ks.loadDevicePublicKey()
    expect(priv?.length).toBe(32)
    expect(pub?.length).toBe(32)
    expect(x25519PrivateFromRaw(priv!).export({ format: 'jwk' })).toMatchObject({ crv: 'X25519' })
  })

  it('is idempotent for createDeviceKey', async () => {
    const ks = fresh()
    await ks.createDeviceKey()
    const first = await ks.loadDevicePublicKey()
    await ks.createDeviceKey()
    expect((await ks.loadDevicePublicKey())!.equals(first!)).toBe(true)
  })

  it('stores base64url on disk and never a PEM', async () => {
    const ks = fresh()
    await ks.createDeviceKey()
    const text = readFileSync(join(ks.dir, 'device.json'), 'utf8')
    expect(text).not.toContain('PRIVATE KEY')
    expect(JSON.parse(text)).toMatchObject({ v: 1, alg: 'x25519' })
  })

  it('deletes the key material', async () => {
    const ks = fresh()
    await ks.createDeviceKey()
    await ks.deleteDeviceKey()
    expect(existsSync(join(ks.dir, 'device.json'))).toBe(false)
    expect(await ks.loadDevicePrivateKey()).toBeUndefined()
  })

  it('throws a typed error on a corrupted file', async () => {
    const ks = fresh()
    await ks.createDeviceKey()
    const file = join(ks.dir, 'device.json')
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { priv: string }
    parsed.priv = 'not-base64!!'
    writeFileSync(file, JSON.stringify(parsed))
    await expect(ks.loadDevicePrivateKey()).rejects.toThrow(KeystoreError)
  })

  it('derives the same shared secret from both sides via ecdh', async () => {
    const a = fresh(); const b = fresh()
    await a.createDeviceKey(); await b.createDeviceKey()
    const sharedA = await a.ecdh((await b.loadDevicePublicKey())!)
    const sharedB = await b.ecdh((await a.loadDevicePublicKey())!)
    expect(sharedA.equals(sharedB)).toBe(true)
  })
})