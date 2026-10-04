import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createPublicKey, diffieHellman, generateKeyPairSync } from 'node:crypto'
import { join } from 'node:path'
import {
  rawPrivateBytes, rawPublicBytes, x25519PrivateFromRaw, x25519PublicFromRaw,
} from '@sealed/license-format'

export { rawPrivateBytes, rawPublicBytes, x25519PrivateFromRaw, x25519PublicFromRaw }

export class KeystoreError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'KeystoreError'
  }
}

export interface Keystore {
  loadDevicePrivateKey(): Promise<Buffer | undefined>
  loadDevicePublicKey(): Promise<Buffer | undefined>
  createDeviceKey(): Promise<void>
  deleteDeviceKey(): Promise<void>
  ecdh(peerPublic: Buffer): Promise<Buffer>
}

const KEY_FILE = 'device.json'

/**
 * M1/M2 的明文密钥库后端：私钥以 base64url 存于 $SEALED_HOME/device.json，POSIX 下 chmod 0600。
 * M2 会加入 DPAPI / Keychain / libsecret 后端，本后端仅作为显式退路保留。
 */
export class FileKeystore implements Keystore {
  readonly dir: string
  private readonly file: string

  constructor(opts: { dir: string }) {
    this.dir = opts.dir
    this.file = join(opts.dir, KEY_FILE)
    mkdirSync(this.dir, { recursive: true })
  }

  async createDeviceKey(): Promise<void> {
    if (existsSync(this.file)) return
    const { privateKey } = generateKeyPairSync('x25519')
    const body = JSON.stringify({ v: 1, alg: 'x25519', priv: rawPrivateBytes(privateKey).toString('base64url') })
    writeFileSync(this.file, body, { encoding: 'utf8', mode: 0o600 })
    try { chmodSync(this.file, 0o600) } catch { /* Windows 依赖用户目录 ACL */ }
  }

  async loadDevicePrivateKey(): Promise<Buffer | undefined> {
    if (!existsSync(this.file)) return undefined
    let parsed: { priv?: unknown }
    try {
      parsed = JSON.parse(readFileSync(this.file, 'utf8')) as { priv?: unknown }
    } catch {
      throw new KeystoreError('device key file is not valid JSON')
    }
    if (typeof parsed.priv !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(parsed.priv)) {
      throw new KeystoreError('device key file has an invalid private key')
    }
    return Buffer.from(parsed.priv, 'base64url')
  }

  async loadDevicePublicKey(): Promise<Buffer | undefined> {
    const priv = await this.loadDevicePrivateKey()
    if (!priv) return undefined
    try {
      return rawPublicBytes(createPublicKey(x25519PrivateFromRaw(priv)))
    } finally {
      priv.fill(0)
    }
  }

  async deleteDeviceKey(): Promise<void> {
    rmSync(this.file, { force: true })
  }

  async ecdh(peerPublic: Buffer): Promise<Buffer> {
    const priv = await this.loadDevicePrivateKey()
    if (!priv) throw new KeystoreError('no device key')
    try {
      return diffieHellman({ privateKey: x25519PrivateFromRaw(priv), publicKey: x25519PublicFromRaw(peerPublic) })
    } finally {
      priv.fill(0)
    }
  }
}