import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'

export const NONCE_BYTES = 12
export const TAG_BYTES = 16

/**
 * AES-256-GCM 加密一个条目。
 *
 * `nonce` 是**测试专用**的注入 seam：生产路径省略它，使用 `randomBytes(12)` 生成的随机 nonce；
 * golden vectors 传入固定 nonce 以获得可复现的密文。它不改变线格式（nonce 仍为 12 字节，
 * tag 仍以 16 字节追加在密文尾部），也不改变 manifest 签名。
 */
export function sealEntry(key: Buffer, aad: Buffer, plaintext: Buffer, nonce?: Buffer): { nonce: Buffer; ct: Buffer } {
  const iv = nonce ?? randomBytes(NONCE_BYTES)
  if (iv.length !== NONCE_BYTES) throw new Error('nonce must be ' + NONCE_BYTES + ' bytes')
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  cipher.setAAD(aad)
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
  return { nonce: iv, ct }
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
