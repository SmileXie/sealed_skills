import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  MAX_ENTRY_BYTES, encodeManifest, readContainer, signManifest, verifyManifestSignature, writeContainer,
} from '../src/index.js'
import type { PackManifest } from '../src/index.js'

const { privateKey, publicKey } = generateKeyPairSync('ed25519')

function buildFixture() {
  const manifest: PackManifest = {
    pack_id: 'com.example.translate', version: '1.0.0', label: '翻译助手', entry_count: 1,
    entries: [{ id: 'meta', type: 'meta', size: 21, trial: true }],
  }
  const signature = signManifest(encodeManifest(manifest), privateKey)
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
    expect(parsed.chunks[0].ct.equals(Buffer.alloc(21, 9))).toBe(true)
    expect(file.subarray(parsed.chunks[0].offset, parsed.chunks[0].offset + 12).equals(Buffer.alloc(12, 3))).toBe(true)
  })

  it('verifies a good signature and rejects a tampered manifest', () => {
    const { manifest, signature } = buildFixture()
    const bytes = encodeManifest(manifest)
    expect(verifyManifestSignature(bytes, signature, publicKey)).toBe(true)
    expect(verifyManifestSignature(encodeManifest({ ...manifest, label: 'x' }), signature, publicKey)).toBe(false)
  })

  it('rejects a bad magic', () => {
    const { file } = buildFixture()
    file[0] = 0x58
    expect(() => readContainer(file)).toThrowError(expect.objectContaining({ code: 'BAD_MAGIC' }))
  })

  it('rejects an unsupported format version', () => {
    const { file } = buildFixture()
    const patched = Buffer.from(file)
    patched[6] = 2
    expect(() => readContainer(patched)).toThrowError(expect.objectContaining({ code: 'BAD_VERSION' }))
  })

  it('rejects a truncated file', () => {
    const { file } = buildFixture()
    expect(() => readContainer(file.subarray(0, file.length - 4))).toThrowError(expect.objectContaining({ code: 'TRUNCATED' }))
  })

  it('rejects a manifest that parses to a non-object', () => {
    const { file } = buildFixture()
    const manifestLen = file.readUInt32BE(8)
    const patched = Buffer.from(file)
    patched.write('null', 12, 'utf8')
    patched.fill(0x20, 12 + 4, 12 + manifestLen)
    expect(() => readContainer(patched)).toThrowError(expect.objectContaining({ code: 'BAD_MANIFEST' }))
  })

  it('rejects an entry larger than the 32 MiB cap', () => {
    const manifest: PackManifest = {
      pack_id: 'com.example.p', version: '1.0.0', label: 'p', entry_count: 1,
      entries: [{ id: 'data:big', type: 'data', size: MAX_ENTRY_BYTES + 1, trial: false }],
    }
    expect(() => writeContainer({ manifest, chunks: [{ id: 'data:big', nonce: Buffer.alloc(12), ct: Buffer.alloc(MAX_ENTRY_BYTES + 1) }], signature: Buffer.alloc(64) }))
      .toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }))
  })

  it('round-trips an entry of exactly the 32 MiB cap', () => {
    const manifest: PackManifest = {
      pack_id: 'com.example.p', version: '1.0.0', label: 'p', entry_count: 1,
      entries: [{ id: 'data:cap', type: 'data', size: MAX_ENTRY_BYTES, trial: false }],
    }
    const ct = Buffer.alloc(MAX_ENTRY_BYTES, 7)
    const file = writeContainer({ manifest, chunks: [{ id: 'data:cap', nonce: Buffer.alloc(12, 1), ct }], signature: Buffer.alloc(64) })
    const parsed = readContainer(file)
    expect(parsed.chunks[0].ct.length).toBe(MAX_ENTRY_BYTES)
    expect(parsed.chunks[0].ct.equals(ct)).toBe(true)
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

  it('rejects a table ctLen that disagrees with the signed manifest size', () => {
    const { file } = buildFixture()
    const manifestLen = file.readUInt32BE(8)
    const sigLen = file.readUInt32BE(12 + manifestLen)
    const tableStart = 12 + manifestLen + 4 + sigLen
    const idLen = file.readUInt32BE(tableStart + 4)
    const ctLenField = tableStart + 4 + 4 + idLen + 8
    const patched = Buffer.from(file)
    patched.writeUInt32BE(patched.readUInt32BE(ctLenField) - 1, ctLenField)
    expect(() => readContainer(patched)).toThrowError(expect.objectContaining({ code: 'TABLE_MISMATCH' }))
  })

  it('rejects a table id that disagrees with the signed manifest (spec §6 TABLE_MISMATCH)', () => {
    const { file } = buildFixture()
    const manifestLen = file.readUInt32BE(8)
    const sigLen = file.readUInt32BE(12 + manifestLen)
    const idStart = 12 + manifestLen + 4 + sigLen + 8
    const patched = Buffer.from(file)
    patched.write('zzzz', idStart, 'utf8')
    expect(() => readContainer(patched)).toThrowError(expect.objectContaining({ code: 'TABLE_MISMATCH' }))
  })

  it('stores the manifest as canonical RFC 8785 bytes', () => {
    const { manifest, file } = buildFixture()
    const parsed = readContainer(file)
    expect(parsed.manifestBytes.equals(encodeManifest(manifest))).toBe(true)
    expect(parsed.manifestBytes.toString('utf8')).toBe(
      '{"entries":[{"id":"meta","size":21,"trial":true,"type":"meta"}],"entry_count":1,"label":"翻译助手","pack_id":"com.example.translate","version":"1.0.0"}',
    )
  })

  it('still verifies a signature over the canonical manifest bytes', () => {
    const { manifest, file } = buildFixture()
    const parsed = readContainer(file)
    expect(verifyManifestSignature(parsed.manifestBytes, parsed.signature, publicKey)).toBe(true)
    expect(verifyManifestSignature(encodeManifest({ ...manifest, version: '9.9.9' }), parsed.signature, publicKey)).toBe(false)
  })

  describe('manifest entry validation', () => {
    function u32(n: number): Buffer { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b }
    function u64(n: number): Buffer { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n), 0); return b }
    function containerWithRawManifest(manifestJson: string): Buffer {
      const manifestBytes = Buffer.from(manifestJson, 'utf8')
      const id = Buffer.from('meta', 'utf8')
      const header = Buffer.concat([Buffer.from('SLDSK1', 'ascii'), Buffer.from([1, 0]), u32(manifestBytes.length)])
      const signature = Buffer.from([0])
      const tableSize = 4 + id.length + 8 + 4
      const offset = header.length + manifestBytes.length + 4 + signature.length + 4 + tableSize
      const table = Buffer.concat([u32(1), u32(id.length), id, u64(offset), u32(0)])
      return Buffer.concat([header, manifestBytes, u32(signature.length), signature, table, Buffer.alloc(12)])
    }

    const badEntries: [string, unknown][] = [
      ['null element', [null]],
      ['non-object element', [7]],
      ['array element', [[]]],
      ['missing id', [{ type: 'meta', size: 0, trial: true }]],
      ['non-string id', [{ id: 7, type: 'meta', size: 0, trial: true }]],
      ['non-string type', [{ id: 'meta', type: 7, size: 0, trial: true }]],
      ['missing type', [{ id: 'meta', size: 0, trial: true }]],
      ['empty type', [{ id: 'meta', type: '', size: 0, trial: true }]],
      ['negative size', [{ id: 'meta', type: 'meta', size: -1, trial: true }]],
      ['non-integer size', [{ id: 'meta', type: 'meta', size: 1.5, trial: true }]],
      ['missing size', [{ id: 'meta', type: 'meta', trial: true }]],
      ['missing trial', [{ id: 'meta', type: 'meta', size: 0 }]],
      ['non-boolean trial', [{ id: 'meta', type: 'meta', size: 0, trial: 'yes' }]],
    ]
    it.each(badEntries)('rejects a %s as BAD_MANIFEST instead of a native TypeError', (_label, entries) => {
      const json = JSON.stringify({ pack_id: 'p', version: '1', label: 'l', entry_count: 1, entries })
      expect(() => readContainer(containerWithRawManifest(json))).toThrowError(expect.objectContaining({ code: 'BAD_MANIFEST' }))
    })

    it('rejects a non-array entries field as BAD_MANIFEST', () => {
      const json = JSON.stringify({ pack_id: 'p', version: '1', label: 'l', entry_count: 1, entries: 'nope' })
      expect(() => readContainer(containerWithRawManifest(json))).toThrowError(expect.objectContaining({ code: 'BAD_MANIFEST' }))
    })

    it('tolerates an unknown entry type for forward compatibility (spec 5.3)', () => {
      const json = JSON.stringify({ pack_id: 'p', version: '1', label: 'l', entry_count: 1, entries: [{ id: 'meta', type: 'future-thing', size: 0, trial: true }] })
      const parsed = readContainer(containerWithRawManifest(json))
      expect(parsed.manifest.entries[0].type).toBe('future-thing')
    })
  })
})