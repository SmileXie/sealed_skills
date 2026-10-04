import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** Thrown for any unreadable or malformed author key file. */
export class AuthorKeyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AuthorKeyError'
  }
}

/** An in-memory Ed25519 author key: the signing key plus its base64url raw public half. */
export interface AuthorKey {
  readonly privateKey: KeyObject
  readonly publicKeyB64: string
}

/** On-disk format of `seal keygen` output. Raw Ed25519 keys, base64url, no padding. */
export interface AuthorKeyFileV1 {
  v: 1
  alg: 'ed25519'
  pub: string
  priv: string
}

export const AUTHOR_KEY_FILE = 'author.key.json'
const RAW_ED25519_RE = /^[A-Za-z0-9_-]{43}$/

function rawPublicB64(key: KeyObject): string {
  return (key.export({ format: 'jwk' }) as { x: string }).x
}

function rawPrivateB64(key: KeyObject): string {
  return (key.export({ format: 'jwk' }) as { d: string }).d
}

/** Generate a fresh Ed25519 AUTHOR keypair (the key that signs pack manifests and licenses). */
export function generateAuthorKey(): AuthorKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  return { privateKey, publicKeyB64: rawPublicB64(publicKey) }
}

/** Persist an author key as documented JSON (base64url raw halves, 0600, BOM-free). */
export function saveAuthorKey(path: string, key: AuthorKey): void {
  const file: AuthorKeyFileV1 = {
    v: 1,
    alg: 'ed25519',
    pub: key.publicKeyB64,
    priv: rawPrivateB64(key.privateKey),
  }
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(file), { encoding: 'utf8', mode: 0o600 })
  try { chmodSync(path, 0o600) } catch { /* Windows relies on the user-directory ACL */ }
}

/** Load and validate an author key file, deriving the public half from the private key. */
export function loadAuthorKey(path: string): AuthorKey {
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    throw new AuthorKeyError('author key file is not valid JSON')
  }
  if (parsed === null || typeof parsed !== 'object') {
    throw new AuthorKeyError('author key file has an unexpected shape')
  }
  const file = parsed as Record<string, unknown>
  if (file.v !== 1 || file.alg !== 'ed25519') {
    throw new AuthorKeyError('author key file is not an Ed25519 author key (v1)')
  }
  if (typeof file.priv !== 'string' || !RAW_ED25519_RE.test(file.priv)) {
    throw new AuthorKeyError('author key file has an invalid private key')
  }
  if (typeof file.pub !== 'string' || !RAW_ED25519_RE.test(file.pub)) {
    throw new AuthorKeyError('author key file has an invalid public key')
  }
  let privateKey: KeyObject
  try {
    privateKey = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: file.priv, x: file.pub }, format: 'jwk' })
  } catch {
    throw new AuthorKeyError('author key file has an invalid Ed25519 key')
  }
  const publicKeyB64 = rawPublicB64(createPublicKey(privateKey))
  if (publicKeyB64 !== file.pub) {
    throw new AuthorKeyError('author key file public key does not match its private key')
  }
  return { privateKey, publicKeyB64 }
}