import { sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto'
import { canonicalJson } from '@sealed/canonical-json'
import { NONCE_BYTES } from './aead.js'

export const PACK_MAGIC = 'SLDSK1'
export const PACK_FORMAT_VERSION = 1
export const MAX_ENTRY_BYTES = 33554432

export type PackEntryType = 'meta' | 'text' | 'script' | 'data'
export interface PackEntryMeta { id: string; type: PackEntryType; size: number; trial: boolean }
export interface PackManifest {
  pack_id: string
  version: string
  label: string
  entry_count: number
  entries: PackEntryMeta[]
}

export type PackErrorCode = 'BAD_MAGIC' | 'BAD_VERSION' | 'TRUNCATED' | 'BAD_MANIFEST' | 'TOO_LARGE' | 'TABLE_MISMATCH'
export class PackFormatError extends Error {
  constructor(readonly code: PackErrorCode, message: string) {
    super(message)
    this.name = 'PackFormatError'
  }
}

const KNOWN_ENTRY_TYPES: readonly PackEntryType[] = ['meta', 'text', 'script', 'data']

/**
 * RFC 8785 (JCS) serialization of the manifest. This is the single source of truth for the
 * bytes that are stored in the container AND signed, so the signature always covers exactly
 * what a reader sees on disk.
 */
export function encodeManifest(manifest: PackManifest): Buffer {
  return Buffer.from(canonicalJson(manifest as unknown as Record<string, unknown>), 'utf8')
}

export function signManifest(manifestBytes: Buffer, privateKey: KeyObject): Buffer {
  return edSign(null, manifestBytes, privateKey)
}

export function verifyManifestSignature(manifestBytes: Buffer, signature: Buffer, publicKey: KeyObject): boolean {
  return edVerify(null, manifestBytes, publicKey, signature)
}

export function writeContainer(input: {
  manifest: PackManifest
  chunks: { id: string; nonce: Buffer; ct: Buffer }[]
  signature: Buffer
}): Buffer {
  const { manifest, chunks, signature } = input
  if (chunks.length !== manifest.entry_count || chunks.length !== manifest.entries.length) {
    throw new PackFormatError('TABLE_MISMATCH', 'chunk count does not match manifest')
  }
  for (const [i, chunk] of chunks.entries()) {
    const meta = manifest.entries[i]
    if (meta.id !== chunk.id) throw new PackFormatError('TABLE_MISMATCH', 'chunk id mismatch at index ' + i)
    if (meta.size > MAX_ENTRY_BYTES) throw new PackFormatError('TOO_LARGE', 'entry ' + meta.id + ' exceeds 32 MiB cap')
    if (meta.size !== chunk.ct.length) throw new PackFormatError('TABLE_MISMATCH', 'chunk size mismatch at index ' + i)
    if (chunk.nonce.length !== NONCE_BYTES) throw new PackFormatError('TABLE_MISMATCH', 'bad nonce length for ' + meta.id)
  }

  const manifestBytes = encodeManifest(manifest)
  const header = Buffer.concat([
    Buffer.from(PACK_MAGIC, 'ascii'),
    Buffer.from([PACK_FORMAT_VERSION, 0]),
    u32(manifestBytes.length),
  ])
  const sigBlock = Buffer.concat([u32(signature.length), signature])
  const tableSize = chunks.reduce((n, c) => n + 4 + Buffer.byteLength(c.id, 'utf8') + 8 + 4, 0)
  let cursor = header.length + manifestBytes.length + sigBlock.length + 4 + tableSize

  const tableParts: Buffer[] = [u32(chunks.length)]
  const chunkParts: Buffer[] = []
  for (const chunk of chunks) {
    const idBytes = Buffer.from(chunk.id, 'utf8')
    tableParts.push(u32(idBytes.length), idBytes, u64(cursor), u32(chunk.ct.length))
    chunkParts.push(chunk.nonce, chunk.ct)
    cursor += NONCE_BYTES + chunk.ct.length
  }
  return Buffer.concat([header, manifestBytes, sigBlock, ...tableParts, ...chunkParts])
}

export function readContainer(buf: Buffer): {
  manifest: PackManifest
  manifestBytes: Buffer
  signature: Buffer
  chunks: { id: string; offset: number; nonce: Buffer; ct: Buffer }[]
} {
  let p = 0
  const need = (n: number) => {
    if (p + n > buf.length) throw new PackFormatError('TRUNCATED', 'unexpected end of pack file')
  }
  need(6)
  if (buf.subarray(0, 6).toString('ascii') !== PACK_MAGIC) throw new PackFormatError('BAD_MAGIC', 'not a sealed pack')
  p = 6
  need(2)
  if (buf[p] !== PACK_FORMAT_VERSION) throw new PackFormatError('BAD_VERSION', 'unsupported pack format version ' + buf[p])
  p += 2
  need(4)
  const manifestLen = buf.readUInt32BE(p); p += 4
  need(manifestLen)
  const manifestBytes = buf.subarray(p, p + manifestLen); p += manifestLen
  need(4)
  const sigLen = buf.readUInt32BE(p); p += 4
  need(sigLen)
  const signature = buf.subarray(p, p + sigLen); p += sigLen
  need(4)
  const count = buf.readUInt32BE(p); p += 4

  let manifest: PackManifest
  try {
    const parsed: unknown = JSON.parse(manifestBytes.toString('utf8'))
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new PackFormatError('BAD_MANIFEST', 'manifest has an unexpected shape')
    }
    manifest = parsed as PackManifest
  } catch (err) {
    if (err instanceof PackFormatError) throw err
    throw new PackFormatError('BAD_MANIFEST', 'manifest is not valid JSON')
  }
  if (typeof manifest.entry_count !== 'number' || !Array.isArray(manifest.entries)) {
    throw new PackFormatError('BAD_MANIFEST', 'manifest has an unexpected shape')
  }
  if (manifest.entry_count !== count || manifest.entries.length !== count) {
    throw new PackFormatError('TABLE_MISMATCH', 'manifest entry_count disagrees with the chunk table')
  }
  for (const entry of manifest.entries) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new PackFormatError('BAD_MANIFEST', 'manifest entry has an unexpected shape')
    }
    const candidate = entry as unknown as Record<string, unknown>
    if (typeof candidate.id !== 'string') {
      throw new PackFormatError('BAD_MANIFEST', 'manifest entry id must be a string')
    }
    if (typeof candidate.type !== 'string' || !KNOWN_ENTRY_TYPES.includes(candidate.type as PackEntryType)) {
      throw new PackFormatError('BAD_MANIFEST', 'manifest entry type is not recognised')
    }
    if (typeof candidate.size !== 'number' || !Number.isInteger(candidate.size) || candidate.size < 0) {
      throw new PackFormatError('BAD_MANIFEST', 'manifest entry size must be a non-negative integer')
    }
    if (typeof candidate.trial !== 'boolean') {
      throw new PackFormatError('BAD_MANIFEST', 'manifest entry trial flag must be a boolean')
    }
  }

  const chunks: { id: string; offset: number; nonce: Buffer; ct: Buffer }[] = []
  for (let i = 0; i < count; i++) {
    need(4)
    const idLen = buf.readUInt32BE(p); p += 4
    need(idLen)
    const id = buf.subarray(p, p + idLen).toString('utf8'); p += idLen
    need(12)
    const offset = Number(buf.readBigUInt64BE(p)); p += 8
    const ctLen = buf.readUInt32BE(p); p += 4
    const declaredSize = manifest.entries[i].size
    if (declaredSize > MAX_ENTRY_BYTES) throw new PackFormatError('TOO_LARGE', 'entry ' + id + ' exceeds 32 MiB cap')
    if (declaredSize !== ctLen) throw new PackFormatError('TABLE_MISMATCH', 'chunk size mismatch at index ' + i)
    if (ctLen > MAX_ENTRY_BYTES) throw new PackFormatError('TOO_LARGE', 'entry ' + id + ' exceeds 32 MiB cap')
    if (offset + NONCE_BYTES + ctLen > buf.length) throw new PackFormatError('TRUNCATED', 'chunk ' + id + ' runs past end of file')
    chunks.push({ id, offset, nonce: buf.subarray(offset, offset + NONCE_BYTES), ct: buf.subarray(offset + NONCE_BYTES, offset + NONCE_BYTES + ctLen) })
  }
  return { manifest, manifestBytes, signature, chunks }
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeUInt32BE(n, 0)
  return b
}
function u64(n: number): Buffer {
  const b = Buffer.alloc(8)
  b.writeBigUInt64BE(BigInt(n), 0)
  return b
}