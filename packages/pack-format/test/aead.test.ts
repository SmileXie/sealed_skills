import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad, openEntry, sealEntry } from '../src/index.js'

const key = deriveEntryKey(Buffer.alloc(32, 1), 'com.x.p', '1.0.0', 'data:blob')
const aad = entryAad('com.x.p', '1.0.0', 'data:blob')

describe('entry AEAD', () => {
  it('round-trips utf8 text', () => {
    const { nonce, ct } = sealEntry(key, aad, Buffer.from('译\n文', 'utf8'))
    expect(ct.length).toBe(Buffer.byteLength('译\n文') + 16)
    expect(openEntry(key, aad, nonce, ct).toString('utf8')).toBe('译\n文')
  })

  it('round-trips binary bytes exactly', () => {
    const blob = Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 37) % 256))
    const { nonce, ct } = sealEntry(key, aad, blob)
    expect(openEntry(key, aad, nonce, ct).equals(blob)).toBe(true)
  })

  it('rejects a flipped ciphertext byte', () => {
    const { nonce, ct } = sealEntry(key, aad, Buffer.from('hello'))
    ct[0] = ct[0] ^ 0xff
    expect(() => openEntry(key, aad, nonce, ct)).toThrow()
  })

  it('rejects a mismatched AAD', () => {
    const { nonce, ct } = sealEntry(key, aad, Buffer.from('hello'))
    expect(() => openEntry(key, entryAad('com.x.p', '1.0.0', 'data:other'), nonce, ct)).toThrow()
  })

  it('rejects ciphertext shorter than the auth tag', () => {
    expect(() => openEntry(key, aad, Buffer.alloc(12), Buffer.alloc(8))).toThrow('ciphertext too short')
  })
})
