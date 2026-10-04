import type { KeyObject } from 'node:crypto'
import { deriveEntryKey } from '@sealed/pack-format'
import {
  LICENSE_GRACE_SECONDS, LICENSE_TTL_SECONDS, signLicense, unb64u, wrapEntryKey,
  x25519PublicFromRaw, type LicensePayload,
} from '@sealed/license-format'
import type { PackRecord } from './store.js'

export interface IssueInput {
  licenseId: string
  sub: string
  pack: PackRecord
  devicePubB64: string
  caps: ('trial' | 'full')[]
  plan: string
  seatLimit: number
  now: number
  entryFilter?: (id: string) => boolean
}

export function issueLicense(input: IssueInput, master: Buffer, signingKey: KeyObject): string {
  const { pack } = input
  const devicePubKey = x25519PublicFromRaw(unb64u(input.devicePubB64))
  const payload: LicensePayload = {
    v: 1,
    lid: input.licenseId,
    sub: input.sub,
    pack: { id: pack.packId, version: pack.version, author_pub: pack.authorPub },
    dev: input.devicePubB64,
    iat: input.now,
    exp: input.now + LICENSE_TTL_SECONDS,
    grace_until: input.now + LICENSE_TTL_SECONDS + LICENSE_GRACE_SECONDS,
    caps: input.caps,
    groups: [input.plan],
    keys: [],
    seats: { plan: input.plan, limit: input.seatLimit },
  }
  for (const entry of pack.entries) {
    if (input.entryFilter && !input.entryFilter(entry.id)) continue
    const ck = deriveEntryKey(master, pack.packId, pack.version, entry.id)
    try {
      payload.keys.push(wrapEntryKey(payload, entry.id, ck, devicePubKey))
    } finally {
      ck.fill(0)
    }
  }
  return signLicense(payload, signingKey)
}
