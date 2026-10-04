import type { PackManifest } from '@sealed/pack-format'

/** Thrown when a master key file is missing, malformed, or the wrong length. */
export class MasterFileError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'MasterFileError'
  }
}

/** On-disk format of the `<pack>.master.json` produced by `seal pack` (spec §7.1 step 5). */
export interface PackMasterFileV1 {
  v: 1
  pack_id: string
  version: string
  master: string
  created_at: string
}

/** Serialize the pack master key for the license server (author-side secret; never shipped). */
export function encodeMasterFile(manifest: Pick<PackManifest, 'pack_id' | 'version'>, master: Buffer, createdAt?: string): string {
  if (master.length !== 32) throw new MasterFileError('master key must be exactly 32 bytes')
  const file: PackMasterFileV1 = {
    v: 1,
    pack_id: manifest.pack_id,
    version: manifest.version,
    master: master.toString('base64url'),
    created_at: createdAt ?? new Date().toISOString(),
  }
  return JSON.stringify(file, null, 2) + '\n'
}

export function parseMasterFile(text: string): { packId: string; version: string; master: Buffer } {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new MasterFileError('master file is not valid JSON')
  }
  if (parsed === null || typeof parsed !== 'object') {
    throw new MasterFileError('master file has an unexpected shape')
  }
  const file = parsed as Record<string, unknown>
  if (file.v !== 1 || typeof file.pack_id !== 'string' || typeof file.version !== 'string' || typeof file.master !== 'string') {
    throw new MasterFileError('master file is not a v1 pack master file')
  }
  const master = Buffer.from(file.master, 'base64url')
  if (master.length !== 32) throw new MasterFileError('master file key is not 32 bytes')
  return { packId: file.pack_id, version: file.version, master }
}