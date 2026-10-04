import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  MAX_ENTRY_BYTES, readContainer, signManifest, verifyManifestSignature, writeContainer,
} from '../src/index.js'
import type { PackManifest } from '../src/index.js'

const { privateKey, publicKey } = generateKeyPairSync('ed25519')

function buildFixture() {
  const manifest: PackManifest = {
    pack_id: 'com.example.translate', version: '1.0.0', label: '翻译助手', entry_count: 1,
    entries: [{ id: 'meta', type: 'meta', size: 21, trial: true }],
  }
  const signature = signManifest(Buffer.from(JSON.stringify(manifest)), privateKey)
  const file = writeContainer({ manifest, chunks: [{ id: 'meta', nonce: Buffer.alloc(12, 3), ct: Buffer.alloc(21, 9) }], signature })
  return { manifest, file, signature }
}

describe('container', () => {
  it('round-trips manifest, signature and chunk offsets', () => {
    const { manifest, file, signature } = buildFixture()
    const parsed = readContainer(file)
    expect(parsed.manifest).toEqual(manifest)
    expect(parsed.signature.equals(signature)).toBe(true)
    expect(parsed.chunks[0].ct.length).toBe(21)
    expect(file.subarray(parsed.chunks[0].offset, parsed.chunks[0].offset + 12).equals(Buffer.alloc(12, 3))).toBe(true)
  })

  it('verifies a good signature and rejects a tampered manifest', () => {
    const { manifest, signature } = buildFixture()
    const bytes = Buffer.from(JSON.stringify(manifest))
    expect(verifyManifestSignature(bytes, signature, publicKey)).toBe(true)
    expect(verifyManifestSignature(Buffer.from(JSON.stringify({ ...manifest, label: 'x' })), signature, publicKey)).toBe(false)
  })

  it('rejects a bad magic', () => {
    const { file } = buildFixture()
    file[0] = 0x58
    expect(() => readContainer(file)).toThrowError(expect.objectContaining({ code: 'BAD_MAGIC' }))
  })

  it('rejects a truncated file', () => {
    const { file } = buildFixture()
    expect(() => readContainer(file.subarray(0, file.length - 4))).toThrowError(expect.objectContaining({ code: 'TRUNCATED' }))
  })

  it('rejects an entry larger than the 32 MiB cap', () => {
    const manifest: PackManifest = {
      pack_id: 'com.example.p', version: '1.0.0', label: 'p', entry_count: 1,
      entries: [{ id: 'data:big', type: 'data', size: MAX_ENTRY_BYTES + 1, trial: false }],
    }
    expect(() => writeContainer({ manifest, chunks: [{ id: 'data:big', nonce: Buffer.alloc(12), ct: Buffer.alloc(MAX_ENTRY_BYTES + 1) }], signature: Buffer.alloc(64) }))
      .toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }))
  })

  it('rejects a chunk table that disagrees with the manifest', () => {
    const { manifest, signature } = buildFixture()
    expect(() => writeContainer({ manifest, chunks: [], signature }))
      .toThrowError(expect.objectContaining({ code: 'TABLE_MISMATCH' }))
  })

  it('rejects a chunk whose ciphertext length disagrees with the manifest size', () => {
    const { manifest, signature } = buildFixture()
    expect(() => writeContainer({ manifest, chunks: [{ id: 'meta', nonce: Buffer.alloc(12), ct: Buffer.alloc(20) }], signature }))
      .toThrowError(expect.objectContaining({ code: 'TABLE_MISMATCH' }))
  })
})