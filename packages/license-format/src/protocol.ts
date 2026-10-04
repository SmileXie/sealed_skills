import { createHmac, hkdfSync, type KeyObject } from 'node:crypto'
import { b64u, unb64u } from './b64.js'
import { x25519PublicFromRaw } from './x25519.js'

export const PROTOCOL_VERSION = 1

export const ENDPOINTS = {
  health: '/v1/health',
  trial: '/v1/trial',
  activate: '/v1/activate',
  renew: '/v1/renew',
  revoke: '/v1/revoke',
  publishPack: '/v1/admin/packs',
} as const

export const LICENSE_TTL_SECONDS = 604800 // 7d
export const LICENSE_GRACE_SECONDS = 259200 // 3d
export const RENEW_THRESHOLD_SECONDS = 172800 // 2d
export const MAX_CLOCK_SKEW_SECONDS = 300
export const NONCE_TTL_SECONDS = 600

export interface PackRef { id: string; version: string }
export interface TrialRequest { device_pub: string; pack: PackRef }
export interface ActivateRequest { device_pub: string; purchase_token: string; pack: PackRef }
export interface RenewRequest { license_id: string; device_pub: string; nonce: string; ts: number; mac: string }
export interface RevokeRequest { license_id?: string; device_pub?: string; seat?: string }
export interface PublishPackRequest {
  pack: PackRef
  author_pub: string
  label: string
  master_b64: string
  trial_entries: string[]
  entries: { id: string; type: string; size: number }[]
}

export type ProtocolErrorCode =
  | 'BAD_REQUEST' | 'PACK_NOT_FOUND' | 'TRIAL_ALREADY_USED' | 'BAD_PURCHASE_TOKEN'
  | 'SEAT_LIMIT' | 'UNKNOWN_LICENSE' | 'BAD_DEVICE_PROOF' | 'REPLAY' | 'REVOKED'
  | 'RATE_LIMITED' | 'UNAUTHORIZED' | 'INTERNAL'

export class ProtocolRequestError extends Error {
  readonly code: ProtocolErrorCode
  constructor(code: ProtocolErrorCode, message: string) {
    super(code + ': ' + message)
    this.name = 'ProtocolRequestError'
    this.code = code
  }
}

export interface LicenseEnvelope { license: string }
export interface HealthEnvelope { ok: true; version: string }
export interface ErrorEnvelope { error: { code: ProtocolErrorCode; message: string } }

const B64URL_32 = /^[A-Za-z0-9_-]{43}$/

export function isRawX25519Pub(value: unknown): boolean {
  if (typeof value !== 'string' || !B64URL_32.test(value)) return false
  return unb64u(value).length === 32
}

export function isRawEd25519Pub(value: unknown): boolean {
  return isRawX25519Pub(value)
}

function bad(message: string): never {
  throw new ProtocolRequestError('BAD_REQUEST', message)
}

function requireObject(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) bad(what + ' must be an object')
  return value as Record<string, unknown>
}

function requireString(value: unknown, what: string): string {
  if (typeof value !== 'string' || value.length === 0) bad(what + ' must be a non-empty string')
  return value
}

function requireDevicePub(value: unknown): string {
  if (!isRawX25519Pub(value)) bad('device_pub must be 32 raw bytes encoded as base64url')
  return value as string
}

export function validatePackRef(value: unknown): PackRef {
  const obj = requireObject(value, 'pack')
  return { id: requireString(obj.id, 'pack.id'), version: requireString(obj.version, 'pack.version') }
}

export function validateTrialRequest(value: unknown): TrialRequest {
  const obj = requireObject(value, 'trial request')
  return { device_pub: requireDevicePub(obj.device_pub), pack: validatePackRef(obj.pack) }
}

export function validateActivateRequest(value: unknown): ActivateRequest {
  const obj = requireObject(value, 'activate request')
  return {
    device_pub: requireDevicePub(obj.device_pub),
    purchase_token: requireString(obj.purchase_token, 'purchase_token'),
    pack: validatePackRef(obj.pack),
  }
}

export function validateRenewRequest(value: unknown): RenewRequest {
  const obj = requireObject(value, 'renew request')
  if (typeof obj.ts !== 'number' || !Number.isInteger(obj.ts)) bad('ts must be an integer unix timestamp in seconds')
  return {
    license_id: requireString(obj.license_id, 'license_id'),
    device_pub: requireDevicePub(obj.device_pub),
    nonce: requireString(obj.nonce, 'nonce'),
    ts: obj.ts,
    mac: requireString(obj.mac, 'mac'),
  }
}

export function validateRevokeRequest(value: unknown): RevokeRequest {
  const record = requireObject(value, 'revoke request')
  const request: RevokeRequest = {}
  if (record.license_id !== undefined) request.license_id = requireString(record.license_id, 'license_id')
  if (record.device_pub !== undefined) request.device_pub = requireString(record.device_pub, 'device_pub')
  if (record.seat !== undefined) request.seat = requireString(record.seat, 'seat')
  if (!request.license_id && !request.device_pub && !request.seat) {
    bad('revoke request needs at least one of license_id, device_pub or seat')
  }
  return request
}

export function validatePublishPackRequest(value: unknown): PublishPackRequest {
  const obj = requireObject(value, 'publish request')
  if (typeof obj.author_pub !== 'string' || !isRawEd25519Pub(obj.author_pub)) bad('author_pub must be 32 raw bytes encoded as base64url')
  if (typeof obj.master_b64 !== 'string' || unb64u(obj.master_b64).length !== 32) bad('master_b64 must be 32 raw bytes encoded as base64url')
  if (!Array.isArray(obj.trial_entries) || !obj.trial_entries.every((id) => typeof id === 'string')) bad('trial_entries must be a string array')
  if (!Array.isArray(obj.entries)) bad('entries must be an array')
  const entries = obj.entries.map((raw) => {
    const entry = requireObject(raw, 'entries[]')
    if (typeof entry.size !== 'number' || !Number.isInteger(entry.size) || entry.size < 0) bad('entries[].size must be a non-negative integer')
    return { id: requireString(entry.id, 'entries[].id'), type: requireString(entry.type, 'entries[].type'), size: entry.size }
  })
  return {
    pack: validatePackRef(obj.pack),
    author_pub: obj.author_pub,
    label: requireString(obj.label, 'label'),
    master_b64: obj.master_b64,
    trial_entries: obj.trial_entries as string[],
    entries,
  }
}

function requireObjectShape(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

export function parseErrorEnvelope(value: unknown): { code: ProtocolErrorCode; message: string } | undefined {
  const root = requireObjectShape(value)
  if (!root) return undefined
  const error = requireObjectShape(root.error)
  if (!error) return undefined
  if (typeof error.code !== 'string' || typeof error.message !== 'string') return undefined
  return { code: error.code as ProtocolErrorCode, message: error.message }
}

const SEP = Buffer.from([0])

export function deviceProofMessage(licenseId: string, nonce: string, ts: number): Buffer {
  return Buffer.concat([Buffer.from(licenseId, 'utf8'), SEP, Buffer.from(nonce, 'utf8'), SEP, Buffer.from(String(ts), 'utf8')])
}

export function deviceProofKey(sharedSecret: Buffer, licenseId: string): Buffer {
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.from(licenseId, 'utf8'), Buffer.from('device-proof:', 'utf8'), 32))
}

export function deviceProofMac(key: Buffer, message: Buffer): string {
  return b64u(createHmac('sha256', key).update(message).digest())
}

/** 服务端设备证明公钥的固定预置形式：43 字符 base64url。 */
export function deviceProofPublicFromRaw(raw: Buffer): KeyObject {
  return x25519PublicFromRaw(raw)
}
