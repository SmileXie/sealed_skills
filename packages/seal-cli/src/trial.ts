import { createPublicKey, randomBytes, type KeyObject } from 'node:crypto'
import { deriveEntryKey, type PackManifest } from '@sealed/pack-format'
import { rawPublicBytes, signLicense, wrapEntryKey, type LicensePayload } from '@sealed/license-format'

export function makeTrialLicense(opts: {
  manifest: PackManifest
  master: Buffer
  devicePublicKey: KeyObject
  trialEntryIds: string[]
  days: number
  signingKey: KeyObject
  now?: number
  lid?: string
}): string {
  const now = Math.floor((opts.now ?? Date.now()) / 1000)
  const devicePub = rawPublicBytes(opts.devicePublicKey).toString('base64url')
  const authorPub = rawPublicBytes(createPublicKey(opts.signingKey)).toString('base64url')
  const payload: LicensePayload = {
    v: 1,
    lid: opts.lid ?? 'lic_trial_' + now + '_' + randomBytes(4).toString('hex'),
    sub: 'trial',
    pack: { id: opts.manifest.pack_id, version: opts.manifest.version, author_pub: authorPub },
    dev: devicePub,
    iat: now,
    exp: now + opts.days * 86400,
    grace_until: now + (opts.days + 3) * 86400,
    caps: ['trial'],
    groups: ['trial'],
    keys: [],
    seats: { plan: 'trial', limit: 1 },
  }
  const wanted = new Set(opts.trialEntryIds)
  for (const entry of opts.manifest.entries) {
    if (!wanted.has(entry.id)) continue
    const ck = deriveEntryKey(opts.master, opts.manifest.pack_id, opts.manifest.version, entry.id)
    try {
      payload.keys.push(wrapEntryKey(payload, entry.id, ck, opts.devicePublicKey))
    } finally {
      ck.fill(0)
    }
  }
  return signLicense(payload, opts.signingKey)
}
