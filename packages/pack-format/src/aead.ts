import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'

export const NONCE_BYTES = 12
export const TAG_BYTES = 16

export function sealEntry(key: Buffer, aad: Buffer, plaintext: Buffer): { nonce: Buffer; ct: Buffer } {
  const nonce = randomBytes(NONCE_BYTES)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad)
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
  return { nonce, ct }
}

export function openEntry(key: Buffer, aad: Buffer, nonce: Buffer, ct: Buffer): Buffer {
  if (ct.length < TAG_BYTES) throw new Error('ciphertext too short')
  const tag = ct.subarray(ct.length - TAG_BYTES)
  const body = ct.subarray(0, ct.length - TAG_BYTES)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body), decipher.final()])
}
