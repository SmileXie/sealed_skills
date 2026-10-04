import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto'
import { b64u, rawPublicBytes, unb64u, x25519PrivateFromRaw } from '@sealed/license-format'
import { ServerError } from './server-errors.js'

export interface ServerKeys {
  licensePrivateKey: KeyObject
  proofPrivateKey: Buffer
  proofPublicB64: string
  masterWrapKey: Buffer
}

function require32(env: NodeJS.ProcessEnv, name: string): Buffer {
  const value = env[name]
  if (!value) throw new ServerError('INTERNAL', name + ' is not configured')
  const raw = unb64u(value)
  if (raw.length !== 32) throw new ServerError('INTERNAL', name + ' must decode to 32 bytes')
  return raw
}

export function loadServerKeys(env: NodeJS.ProcessEnv): ServerKeys {
  const licenseRaw = require32(env, 'SEALED_SERVER_LICENSE_KEY')
  const proofPrivateKey = require32(env, 'SEALED_SERVER_PROOF_KEY')
  const masterWrapKey = require32(env, 'SEALED_SERVER_MASTER_KEY')
  let licensePrivateKey: KeyObject
  try {
    // Node 24 requires the `x` property to be a string even though it derives the
    // public key from `d`; an empty placeholder is accepted and ignored.
    licensePrivateKey = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: b64u(licenseRaw), x: '' }, format: 'jwk' })
  } catch {
    throw new ServerError('INTERNAL', 'SEALED_SERVER_LICENSE_KEY is not a valid Ed25519 private key')
  }
  return {
    licensePrivateKey,
    proofPrivateKey,
    proofPublicB64: b64u(rawPublicBytes(createPublicKey(x25519PrivateFromRaw(proofPrivateKey)))),
    masterWrapKey,
  }
}

export function serverLicensePublicB64(keys: ServerKeys): string {
  return b64u(rawPublicBytes(createPublicKey(keys.licensePrivateKey)))
}
