import { randomBytes } from 'node:crypto'
import {
  LICENSE_TTL_SECONDS, LICENSE_GRACE_SECONDS, validateActivateRequest, validateTrialRequest,
  type ProtocolErrorCode,
} from '@sealed/license-format'
import { issueLicense } from './issue.js'
import { unwrapMaster } from './master-store.js'
import { HttpError } from './http.js'
import type { ServerKeys } from './keys.js'
import type { Store } from './store.js'

export function generateLicenseId(prefix: string, now: number): string {
  return 'lic_' + prefix + '_' + now + '_' + randomBytes(4).toString('hex')
}

export interface RouteResult { status: number; body: unknown }

function requirePack(store: Store, packId: string, version: string) {
  const pack = store.getPack(packId, version)
  if (!pack) throw new HttpError(404, 'PACK_NOT_FOUND', 'unknown pack or version')
  return pack
}

function unwrapPackMaster(store: Store, keys: ServerKeys, packId: string, version: string): Buffer {
  const record = requirePack(store, packId, version)
  const master = unwrapMaster(record.masterWrapped, keys.masterWrapKey)
  if (master.length !== 32) throw new HttpError(500, 'INTERNAL', 'stored master key is malformed')
  return master
}

export function handleTrial(store: Store, keys: ServerKeys, body: unknown, now: number): RouteResult {
  const request = validateTrialRequest(body)
  const pack = requirePack(store, request.pack.id, request.pack.version)
  const existing = store.getTrial(request.device_pub, pack.packId, pack.version)
  if (existing) throw new HttpError(409, 'TRIAL_ALREADY_USED', 'this device already used the trial for this pack')
  const master = unwrapPackMaster(store, keys, pack.packId, pack.version)
  const trialSet = new Set(pack.trialEntries)
  const licenseId = generateLicenseId('trial', now)
  let token: string
  try {
    token = issueLicense({
      licenseId, sub: 'trial:' + request.device_pub.slice(0, 8), pack, devicePubB64: request.device_pub,
      caps: ['trial'], plan: 'trial', seatLimit: 1, now, entryFilter: (id) => trialSet.has(id),
    }, master, keys.licensePrivateKey)
  } finally {
    master.fill(0)
  }
  store.putTrial(request.device_pub, pack.packId, pack.version, licenseId, now)
  store.appendAudit({ at: now, action: 'trial', actor: 'client', subject: licenseId, detail: pack.packId + '@' + pack.version })
  return { status: 200, body: { license: token } }
}

export function handleActivate(store: Store, keys: ServerKeys, body: unknown, now: number): RouteResult {
  const request = validateActivateRequest(body)
  const purchase = store.getPurchase(request.purchase_token)
  if (!purchase) throw new HttpError(401, 'BAD_PURCHASE_TOKEN', 'purchase token is unknown')
  if (purchase.expiresAt !== undefined && purchase.expiresAt <= now) throw new HttpError(401, 'BAD_PURCHASE_TOKEN', 'purchase token has expired')
  if (purchase.packId !== request.pack.id || purchase.version !== request.pack.version) throw new HttpError(404, 'PACK_NOT_FOUND', 'purchase token is for a different pack')
  const pack = requirePack(store, purchase.packId, purchase.version)
  const existing = store.getLicenseForDevice(pack.packId, pack.version, request.device_pub)
  if (existing) {
    const master = unwrapPackMaster(store, keys, pack.packId, pack.version)
    try {
      const token = issueLicense({
        licenseId: existing.licenseId, sub: existing.sub, pack, devicePubB64: request.device_pub,
        caps: ['full'], plan: purchase.plan, seatLimit: purchase.seats, now,
      }, master, keys.licensePrivateKey)
      return { status: 200, body: { license: token } }
    } finally { master.fill(0) }
  }
  if (store.countSeats(purchase.sub, pack.packId, pack.version) >= purchase.seats) {
    throw new HttpError(409, 'SEAT_LIMIT', 'all seats for this purchase are in use')
  }
  const master = unwrapPackMaster(store, keys, pack.packId, pack.version)
  const licenseId = generateLicenseId('full', now)
  let token: string
  try {
    token = issueLicense({
      licenseId, sub: purchase.sub, pack, devicePubB64: request.device_pub,
      caps: ['full'], plan: purchase.plan, seatLimit: purchase.seats, now,
    }, master, keys.licensePrivateKey)
  } finally { master.fill(0) }
  store.upsertDevice(request.device_pub, purchase.sub, now)
  store.putSeat({ sub: purchase.sub, packId: pack.packId, version: pack.version, devicePub: request.device_pub, licenseId }, now)
  store.putLicense({
    licenseId, sub: purchase.sub, packId: pack.packId, version: pack.version, devicePub: request.device_pub,
    caps: ['full'], plan: purchase.plan, seatLimit: purchase.seats,
    iat: now, exp: now + LICENSE_TTL_SECONDS, graceUntil: now + LICENSE_TTL_SECONDS + LICENSE_GRACE_SECONDS, revoked: false,
  })
  store.appendAudit({ at: now, action: 'activate', actor: 'client', subject: licenseId, detail: pack.packId + '@' + pack.version })
  return { status: 200, body: { license: token } }
}
