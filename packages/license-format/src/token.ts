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
  let raw: { payload?: unknown; sig?: unknown }
  try {
    raw = JSON.parse(text) as { payload?: unknown; sig?: unknown }
  } catch {
    throw new LicenseError('LICENSE_MALFORMED', 'license is not JSON')
  }
  if (typeof raw.payload !== 'string' || typeof raw.sig !== 'string') {
    throw new LicenseError('LICENSE_MALFORMED', 'license is missing payload or sig')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(unb64u(raw.payload).toString('utf8'))
  } catch {
    throw new LicenseError('LICENSE_MALFORMED', 'license payload is not JSON')
  }
  const p = parsed as LicensePayload
  const ok = p !== null && typeof p === 'object' && p.v === 1 &&
    typeof p.lid === 'string' && typeof p.sub === 'string' && typeof p.dev === 'string' &&
    typeof p.iat === 'number' && typeof p.exp === 'number' && typeof p.grace_until === 'number' &&
    Array.isArray(p.keys) && Array.isArray(p.caps) && Array.isArray(p.groups) &&
    p.pack !== undefined && typeof p.pack.id === 'string' && typeof p.pack.version === 'string' && typeof p.pack.author_pub === 'string'
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
