const SEP = Buffer.from([0x00])

/** 用 0x00 分隔拼接，避免 id/version/pack 拼接歧义。 */
export function entryAad(packId: string, version: string, entryId: string): Buffer {
  return Buffer.concat([
    Buffer.from(packId, 'utf8'),
    SEP,
    Buffer.from(version, 'utf8'),
    SEP,
    Buffer.from(entryId, 'utf8'),
  ])
}
