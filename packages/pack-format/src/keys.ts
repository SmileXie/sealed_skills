import { hkdfSync } from 'node:crypto'

export const KEY_BYTES = 32

export function deriveEntryKey(master: Buffer, packId: string, version: string, entryId: string): Buffer {
  const salt = Buffer.concat([Buffer.from(packId, 'utf8'), Buffer.from([0x00]), Buffer.from(version, 'utf8')])
  const info = Buffer.concat([Buffer.from('entry:', 'utf8'), Buffer.from(entryId, 'utf8')])
  return Buffer.from(hkdfSync('sha256', master, salt, info, KEY_BYTES))
}
