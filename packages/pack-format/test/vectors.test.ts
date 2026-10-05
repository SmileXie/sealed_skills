import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad, openEntry, sealEntry } from '../src/index.js'

/**
 * Golden-vector conformance for the PUBLIC `.sealedpack` v1 format.
 *
 * The vectors in `test-vectors/pack-format.json` are TEST-ONLY (fixed master/nonce). This test
 * recomputes every value from the shipped implementation and asserts byte-for-byte equality, so a
 * third-party loader can trust the vectors and a format regression fails loudly.
 */
interface PackVector {
  name: string
  pack_id: string
  version: string
  entry_id: string
  master_hex: string
  nonce_hex: string
  plaintext_utf8: string
  ck_hex: string
  aad_hex: string
  ct_hex: string
}

const doc = JSON.parse(
  readFileSync(new URL('../../../test-vectors/pack-format.json', import.meta.url), 'utf8'),
) as { format: string; format_version: number; vectors: PackVector[] }

describe('golden vectors: pack-format', () => {
  it('declares the format and enough coverage', () => {
    expect(doc.format).toBe('sealed-skills/pack-format')
    expect(doc.format_version).toBe(1)
    expect(doc.vectors.length).toBeGreaterThanOrEqual(3)
    for (const name of ['meta-ascii', 'text-unicode', 'script-multiline']) {
      expect(doc.vectors.some((v) => v.name === name)).toBe(true)
    }
  })

  for (const v of doc.vectors) {
    it('reproduces vector ' + v.name, () => {
      const master = Buffer.from(v.master_hex, 'hex')
      expect(master.length).toBe(32)

      const ck = deriveEntryKey(master, v.pack_id, v.version, v.entry_id)
      expect(ck.toString('hex')).toBe(v.ck_hex)

      const aad = entryAad(v.pack_id, v.version, v.entry_id)
      expect(aad.toString('hex')).toBe(v.aad_hex)

      const nonce = Buffer.from(v.nonce_hex, 'hex')
      const plaintext = Buffer.from(v.plaintext_utf8, 'utf8')
      const sealed = sealEntry(ck, aad, plaintext, nonce)
      expect(sealed.nonce.toString('hex')).toBe(v.nonce_hex)
      expect(sealed.ct.toString('hex')).toBe(v.ct_hex)

      expect(openEntry(ck, aad, sealed.nonce, sealed.ct).toString('utf8')).toBe(v.plaintext_utf8)
    })
  }
})