import { sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto'
import { canonicalJson } from '@sealed/canonical-json'
import { b64u, unb64u } from './b64.js'
import { LicenseError } from './x25519.js'
import type { LicensePayload } from './types.js'

function payloadBytes(payload: LicensePayload): Buffer {
  return Buffer.from(canonicalJson(payload as unknown as Record<string, unknown>), 'utf8')
}

export function signLicense(payload: LicensePayload, privateKey: KeyObject): string {
  const bytes = payloadBytes(payload)
  return JSON.stringify({ payload: b64u(bytes), sig: b64u(edSign(null, bytes, privateKey)) })
}

export function parseLicense(text: string): { payload: LicensePayload; payloadB64: string; sig: string } {
  let parsedDoc: unknown
  try {
    parsedDoc = JSON.parse(text)
  } catch {
    throw new LicenseError('LICENSE_MALFORMED', 'license is not JSON')
  }
  if (parsedDoc === null || typeof parsedDoc !== 'object' || Array.isArray(parsedDoc)) {
    throw new LicenseError('LICENSE_MALFORMED', 'license is not a JSON object')
  }
  const raw = parsedDoc as { payload?: unknown; sig?: unknown }
  if (typeof raw.payload !== 'string' || typeof raw.sig !== 'string') {
    throw new LicenseError('LICENSE_MALFORMED', 'license is missing payload or sig')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(unb64u(raw.payload).toString('utf8'))
  } catch {
    throw new LicenseError('LICENSE_MALFORMED', 'license payload is not JSON')
  }
  if (parsed === null || typeof parsed !== 'object') {
    throw new LicenseError('LICENSE_MALFORMED', 'license payload has the wrong shape')
  }
  const p = parsed as LicensePayload
  const pack = (p as unknown as { pack?: unknown }).pack
  const seats = (p as unknown as { seats?: unknown }).seats
  // Spec license-format.md §4 step 1: a shape error anywhere below is LICENSE_MALFORMED, so a
  // signed token with malformed grants/seats is rejected up front rather than failing later.
  const isStringArray = (value: unknown): boolean =>
    Array.isArray(value) && value.every((item) => typeof item === 'string')
  const isGrant = (value: unknown): boolean => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
    const grant = value as Record<string, unknown>
    return typeof grant.eid === 'string' && typeof grant.eph === 'string' &&
      typeof grant.n === 'string' && typeof grant.c === 'string'
  }
  const ok = p.v === 1 &&
    typeof p.lid === 'string' && typeof p.sub === 'string' && typeof p.dev === 'string' &&
    typeof p.iat === 'number' && typeof p.exp === 'number' && typeof p.grace_until === 'number' &&
    isStringArray(p.caps) && isStringArray(p.groups) &&
    Array.isArray(p.keys) && p.keys.every(isGrant) &&
    typeof pack === 'object' && pack !== null &&
    typeof (pack as { id?: unknown }).id === 'string' &&
    typeof (pack as { version?: unknown }).version === 'string' &&
    typeof (pack as { author_pub?: unknown }).author_pub === 'string' &&
    typeof seats === 'object' && seats !== null && !Array.isArray(seats) &&
    typeof (seats as { plan?: unknown }).plan === 'string' &&
    typeof (seats as { limit?: unknown }).limit === 'number'
  if (!ok) throw new LicenseError('LICENSE_MALFORMED', 'license payload has the wrong shape')
  return { payload: p, payloadB64: raw.payload, sig: raw.sig }
}

export function verifyLicense(text: string, publicKeys: KeyObject[]): LicensePayload {
  const { payload, payloadB64, sig } = parseLicense(text)
  const bytes = unb64u(payloadB64)
  if (!bytes.equals(payloadBytes(payload))) {
    throw new LicenseError('LICENSE_NOT_CANONICAL', 'license payload is not canonically encoded')
  }
  const signature = unb64u(sig)
  if (!publicKeys.some((key) => edVerify(null, bytes, key, signature))) {
    throw new LicenseError('LICENSE_BAD_SIGNATURE', 'license signature is not trusted')
  }
  return payload
}

export function licenseStatus(payload: LicensePayload, nowMs: number): 'active' | 'grace' | 'expired' {
  const now = Math.floor(nowMs / 1000)
  if (now < payload.exp) return 'active'
  if (now < payload.grace_until) return 'grace'
  return 'expired'
}
