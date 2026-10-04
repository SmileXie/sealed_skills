import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { b64u, unb64u } from '@sealed/license-format'
import { ServerError } from './server-errors.js'

const NONCE_BYTES = 12

/** master key 静态加密：`v1.<b64u nonce>.<b64u ciphertext||tag>`。 */
export function wrapMaster(master: Buffer, masterWrapKey: Buffer): string {
  const nonce = randomBytes(NONCE_BYTES)
  const cipher = createCipheriv('aes-256-gcm', masterWrapKey, nonce)
  const ct = Buffer.concat([cipher.update(master), cipher.final(), cipher.getAuthTag()])
  return 'v1.' + b64u(nonce) + '.' + b64u(ct)
}

export function unwrapMaster(wrapped: string, masterWrapKey: Buffer): Buffer {
  const parts = wrapped.split('.')
  if (parts.length !== 3 || parts[0] !== 'v1') throw new ServerError('INTERNAL', 'stored master key is malformed')
  const nonce = unb64u(parts[1])
  const ct = unb64u(parts[2])
  if (nonce.length !== NONCE_BYTES || ct.length < 16) throw new ServerError('INTERNAL', 'stored master key is malformed')
  const tag = ct.subarray(ct.length - 16)
  const body = ct.subarray(0, ct.length - 16)
  const decipher = createDecipheriv('aes-256-gcm', masterWrapKey, nonce)
  decipher.setAuthTag(tag)
  try {
    return Buffer.concat([decipher.update(body), decipher.final()])
  } catch {
    throw new ServerError('INTERNAL', 'could not decrypt the stored master key')
  }
}
