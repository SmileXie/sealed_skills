import { chmodSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { diffieHellman, randomBytes, type KeyObject } from 'node:crypto'
import { join } from 'node:path'
import {
  ENDPOINTS, LicenseError, MAX_CLOCK_SKEW_SECONDS, RENEW_THRESHOLD_SECONDS,
  deviceProofKey, deviceProofMac, deviceProofMessage, isRawX25519Pub, licenseStatus,
  parseErrorEnvelope, unb64u, verifyLicense,
  type LicensePayload, type PackRef,
} from '@sealed/license-format'
import { x25519PrivateFromRaw, x25519PublicFromRaw, type Keystore } from './keystore.js'

export type LicenseDenialCode =
  | 'NO_LICENSE' | 'LICENSE_REVOKED' | 'LICENSE_EXPIRED' | 'CLOCK_UNTRUSTED'
  | 'SERVER_REJECTED' | 'SERVER_UNAVAILABLE' | 'BAD_SERVER_LICENSE'

export class LicenseDenied extends Error {
  constructor(readonly code: LicenseDenialCode, message: string) {
    super(message)
    this.name = 'LicenseDenied'
  }
}

export interface Entitlement {
  state: 'active' | 'grace'
  license: string
  payload: LicensePayload
  source: 'cache' | 'network'
}

export interface LicenseClientOptions {
  // 两者都可选：纯离线（只读缓存 / 导入离线 license）时无需配置；在线方法在调用时才校验。
  serverUrl?: string
  serverProofPubB64?: string
  keystore: Keystore
  homeDir: string
  trustedLicenseKeys: KeyObject[]
  fetchFn?: typeof fetch
  now?: () => number
  retry?: { attempts: number; baseMs: number; maxMs: number }
}

interface ClockState { v: 1; lastSeenMs: number }
type Envelope = { status: number; body: Record<string, unknown> }

export class LicenseClient {
  private readonly fetchFn: typeof fetch
  private readonly retry: { attempts: number; baseMs: number; maxMs: number }
  private readonly licensesDir: string
  private readonly clockPath: string
  private devicePub?: string

  constructor(private readonly opts: LicenseClientOptions) {
    this.fetchFn = opts.fetchFn ?? globalThis.fetch
    this.retry = opts.retry ?? { attempts: 3, baseMs: 200, maxMs: 2000 }
    this.licensesDir = join(opts.homeDir, 'licenses')
    this.clockPath = join(opts.homeDir, 'clock.json')
    mkdirSync(this.licensesDir, { recursive: true })
  }

  async ensureLicense(pack: PackRef): Promise<Entitlement> {
    await this.devicePublicB64()
    const cached = this.readCached(pack)
    const rolledBack = this.clockRolledBack()
    if (cached && !rolledBack) {
      const status = licenseStatus(cached.payload, this.nowMs())
      const secondsLeft = cached.payload.exp - Math.floor(this.nowMs() / 1000)
      if (status === 'active' && secondsLeft > RENEW_THRESHOLD_SECONDS) {
        return this.accept(cached.payload.pack, cached.license, 'cache')
      }
    }
    if (cached) {
      let renewError: unknown
      try {
        return await this.renew(pack, cached.license)
      } catch (error) {
        renewError = error
      }
      if (renewError instanceof LicenseDenied && renewError.code === 'SERVER_UNAVAILABLE') {
        if (rolledBack) throw new LicenseDenied('CLOCK_UNTRUSTED', 'the local clock moved backwards and the license server is unreachable')
        const status = licenseStatus(cached.payload, this.nowMs())
        if (status !== 'expired') return { state: status, license: cached.license, payload: cached.payload, source: 'cache' }
      }
      throw renewError
    }
    throw new LicenseDenied('NO_LICENSE', 'no license is available for this pack')
  }

  async activate(pack: PackRef, purchaseToken: string): Promise<Entitlement> {
    await this.devicePublicB64()
    const response = await this.post(ENDPOINTS.activate, { device_pub: this.devicePub, purchase_token: purchaseToken, pack })
    if (response.status !== 200) throw this.rejected(response)
    return this.accept(pack, String(response.body.license), 'network')
  }

  async activateTrial(pack: PackRef): Promise<Entitlement> {
    await this.devicePublicB64()
    const response = await this.post(ENDPOINTS.trial, { device_pub: this.devicePub, pack })
    if (response.status !== 200) throw this.rejected(response)
    return this.accept(pack, String(response.body.license), 'network')
  }

  async renew(pack: PackRef, licenseText: string): Promise<Entitlement> {
    await this.devicePublicB64()
    const payload = this.parseTrusted(licenseText)
    for (let attempt = 0; attempt < 2; attempt++) {
      const proof = await this.proofFor(payload.lid)
      const response = await this.post(ENDPOINTS.renew, {
        license_id: payload.lid, device_pub: this.devicePub, nonce: proof.nonce, ts: proof.ts, mac: proof.mac,
      })
      if (response.status === 200) return this.accept(pack, String(response.body.license), 'network')
      const parsed = parseErrorEnvelope(response.body)
      if (parsed?.code === 'REPLAY') continue
      if (parsed?.code === 'REVOKED') {
        rmSync(join(this.licensesDir, payload.lid + '.license.json'), { force: true })
        throw new LicenseDenied('LICENSE_REVOKED', parsed.message)
      }
      throw this.rejected(response)
    }
    throw new LicenseDenied('SERVER_REJECTED', 'the license server kept rejecting the renewal nonce')
  }

  /** 导入离线预置的 license（校验签名与设备绑定后落盘）。 */
  async importLicense(license: string, pack?: PackRef): Promise<Entitlement> {
    await this.devicePublicB64()
    const payload = this.parseTrusted(license)
    if (pack && (payload.pack.id !== pack.id || payload.pack.version !== pack.version)) {
      throw new LicenseDenied('BAD_SERVER_LICENSE', 'license is for a different pack')
    }
    return this.accept(payload.pack, license, 'cache')
  }

  private parseTrusted(license: string): LicensePayload {
    try {
      return verifyLicense(license, this.opts.trustedLicenseKeys)
    } catch (error) {
      throw new LicenseDenied('BAD_SERVER_LICENSE', error instanceof LicenseError ? error.message : 'license is not trusted')
    }
  }

  private accept(pack: PackRef, license: string, source: 'cache' | 'network'): Entitlement {
    const payload = this.parseTrusted(license)
    if (payload.pack.id !== pack.id || payload.pack.version !== pack.version) {
      throw new LicenseDenied('BAD_SERVER_LICENSE', 'license is for a different pack')
    }
    if (payload.dev !== this.devicePub) throw new LicenseDenied('BAD_SERVER_LICENSE', 'license is bound to a different device')
    this.writeFile(join(this.licensesDir, payload.lid + '.license.json'), license)
    this.advanceClock(payload.iat * 1000)
    const status = licenseStatus(payload, this.nowMs())
    return { state: status === 'grace' ? 'grace' : 'active', license, payload, source }
  }

  private readCached(pack: PackRef): { license: string; payload: LicensePayload } | undefined {
    let names: string[]
    try {
      names = readdirSync(this.licensesDir)
    } catch {
      return undefined
    }
    for (const name of names) {
      if (!name.endsWith('.license.json')) continue
      const text = readFileSync(join(this.licensesDir, name), 'utf8')
      let payload: LicensePayload
      try {
        payload = verifyLicense(text, this.opts.trustedLicenseKeys)
      } catch {
        continue
      }
      if (payload.pack.id === pack.id && payload.pack.version === pack.version) return { license: text, payload }
    }
    return undefined
  }

  private async devicePublicB64(): Promise<string> {
    if (!this.devicePub) {
      const pub = await this.opts.keystore.loadDevicePublicKey()
      if (!pub) throw new LicenseDenied('NO_LICENSE', 'no device key is available')
      this.devicePub = pub.toString('base64url')
    }
    return this.devicePub
  }

  private async proofFor(licenseId: string): Promise<{ nonce: string; ts: number; mac: string }> {
    const nonce = randomBytes(16).toString('base64url')
    const ts = Math.floor(this.nowMs() / 1000)
    const proofPub = this.opts.serverProofPubB64
    if (!proofPub || !isRawX25519Pub(proofPub)) throw new LicenseDenied('SERVER_UNAVAILABLE', 'no license server proof key is configured')
    const peer = unb64u(proofPub)
    let shared: Buffer
    if (this.opts.keystore.ecdh) {
      shared = await this.opts.keystore.ecdh(peer)
    } else {
      const raw = await this.opts.keystore.loadDevicePrivateKey()
      if (!raw) throw new LicenseDenied('NO_LICENSE', 'no device key is available')
      try {
        shared = diffieHellman({ privateKey: x25519PrivateFromRaw(raw), publicKey: x25519PublicFromRaw(peer) })
      } finally {
        raw.fill(0)
      }
    }
    return { nonce, ts, mac: deviceProofMac(deviceProofKey(shared, licenseId), deviceProofMessage(licenseId, nonce, ts)) }
  }

  private async post(path: string, body: unknown): Promise<Envelope> {
    if (!this.opts.serverUrl) throw new LicenseDenied('SERVER_UNAVAILABLE', 'no license server URL is configured')
    const url = this.opts.serverUrl.replace(/\/+$/, '') + path
    let lastError: unknown
    for (let attempt = 0; attempt < this.retry.attempts; attempt++) {
      try {
        const res = await this.fetchFn(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
        if (res.status >= 500) {
          lastError = new Error('license server responded ' + res.status)
          await this.backoff(attempt)
          continue
        }
        const parsed: unknown = await res.json().catch(() => ({}))
        return { status: res.status, body: (parsed ?? {}) as Record<string, unknown> }
      } catch (error) {
        lastError = error
        await this.backoff(attempt)
      }
    }
    throw new LicenseDenied('SERVER_UNAVAILABLE', 'license server is unreachable: ' + (lastError instanceof Error ? lastError.message : String(lastError)))
  }

  private async backoff(attempt: number): Promise<void> {
    const capped = Math.min(this.retry.maxMs, this.retry.baseMs * 2 ** attempt)
    await new Promise((resolve) => setTimeout(resolve, capped * (0.5 + Math.random() * 0.5)))
  }

  private rejected(response: Envelope): LicenseDenied {
    const parsed = parseErrorEnvelope(response.body)
    if (parsed?.code === 'REVOKED') return new LicenseDenied('LICENSE_REVOKED', parsed.message)
    return new LicenseDenied('SERVER_REJECTED', 'license server rejected the request (' + response.status + ')')
  }

  private nowMs(): number {
    return this.opts.now ? this.opts.now() : Date.now()
  }

  private readClock(): ClockState {
    try {
      const parsed = JSON.parse(readFileSync(this.clockPath, 'utf8')) as Partial<ClockState>
      if (parsed && parsed.v === 1 && typeof parsed.lastSeenMs === 'number') return { v: 1, lastSeenMs: parsed.lastSeenMs }
    } catch {
      // 缺少或损坏的时钟文件视为“没有观测锚点”。
    }
    return { v: 1, lastSeenMs: 0 }
  }

  private clockRolledBack(): boolean {
    return this.nowMs() + MAX_CLOCK_SKEW_SECONDS * 1000 < this.readClock().lastSeenMs
  }

  private advanceClock(ms: number): void {
    if (ms <= this.readClock().lastSeenMs) return
    this.writeFile(this.clockPath, JSON.stringify({ v: 1, lastSeenMs: ms }))
  }

  private writeFile(path: string, text: string): void {
    const tmp = path + '.tmp'
    writeFileSync(tmp, text, { encoding: 'utf8', mode: 0o600 })
    try { chmodSync(tmp, 0o600) } catch { /* Windows 依赖用户目录 ACL */ }
    renameSync(tmp, path)
  }
}
