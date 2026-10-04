import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto'

export class LicenseError extends Error {
  constructor(readonly code: string, message: string) {
    super(`${code}: ${message}`)
    this.name = 'LicenseError'
  }
}

// X25519 的 PKCS8 / SPKI DER 前缀后面就是 32 字节原始密钥，
// 用 DER 而不是 JWK，避免不同 Node 版本对 OKP JWK 私有键（缺少 x）的处理差异。
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')

export function x25519PublicFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new LicenseError('LICENSE_MALFORMED', 'X25519 public key must be 32 bytes')
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' })
}

export function x25519PrivateFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new LicenseError('LICENSE_MALFORMED', 'X25519 private key must be 32 bytes')
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' })
}

export function rawPublicBytes(key: KeyObject): Buffer {
  const der = key.export({ format: 'der', type: 'spki' }) as Buffer
  return der.subarray(der.length - 32)
}

export function rawPrivateBytes(key: KeyObject): Buffer {
  const der = key.export({ format: 'der', type: 'pkcs8' }) as Buffer
  return der.subarray(der.length - 32)
}
