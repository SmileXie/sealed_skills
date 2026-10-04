import { createCipheriv, createDecipheriv, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, type KeyObject } from 'node:crypto'
import { b64u, unb64u } from './b64.js'
import { LicenseError, rawPublicBytes, x25519PublicFromRaw } from './x25519.js'
import type { LicenseGrant, LicensePayload } from './types.js'

const SEP = Buffer.from([0x00])

export function wrapAad(lid: string, eid: string): Buffer {
  return Buffer.concat([Buffer.from(lid, 'utf8'), SEP, Buffer.from(eid, 'utf8')])
}

function kek(shared: Buffer, lid: string, eid: string): Buffer {
  const info = Buffer.concat([Buffer.from('wrap:', 'utf8'), Buffer.from(eid, 'utf8')])
  return Buffer.from(hkdfSync('sha256', shared, Buffer.from(lid, 'utf8'), info, 32))
}

export function wrapEntryKey(
  payload: Pick<LicensePayload, 'lid'>,
  eid: string,
  contentKey: Buffer,
  devicePublicKey: KeyObject,
): LicenseGrant {
  const ephemeral = generateKeyPairSync('x25519')
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: devicePublicKey })
  const key = kek(shared, payload.lid, eid)
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(wrapAad(payload.lid, eid))
  const ct = Buffer.concat([cipher.update(contentKey), cipher.final(), cipher.getAuthTag()])
  return { eid, eph: b64u(rawPublicBytes(ephemeral.publicKey)), n: b64u(nonce), c: b64u(ct) }
}

export function unwrapEntryKey(payload: LicensePayload, eid: string, devicePrivateKey: KeyObject): Buffer {
  const grant = payload.keys.find((k) => k.eid === eid)
  if (!grant) throw new LicenseError('LICENSE_NO_GRANT', 'license grants no key for ' + eid)
  const shared = diffieHellman({ privateKey: devicePrivateKey, publicKey: x25519PublicFromRaw(unb64u(grant.eph)) })
  const key = kek(shared, payload.lid, eid)
  const ct = unb64u(grant.c)
  if (ct.length < 16) throw new LicenseError('LICENSE_UNWRAP_FAILED', 'wrapped key is too short')
  const tag = ct.subarray(ct.length - 16)
  const body = ct.subarray(0, ct.length - 16)
  const decipher = createDecipheriv('aes-256-gcm', key, unb64u(grant.n))
  decipher.setAAD(wrapAad(payload.lid, eid))
  decipher.setAuthTag(tag)
  try {
    return Buffer.concat([decipher.update(body), decipher.final()])
  } catch {
    throw new LicenseError('LICENSE_UNWRAP_FAILED', 'could not unwrap the entry key with this device key')
  }
}
