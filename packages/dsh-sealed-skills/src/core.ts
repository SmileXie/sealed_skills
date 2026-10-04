import { createPublicKey, type KeyObject } from 'node:crypto'
import { entryAad, openEntry, readContainer, verifyManifestSignature } from '@sealed/pack-format'
import { LicenseError, licenseStatus, unwrapEntryKey, verifyLicense, type LicensePayload } from '@sealed/license-format'
import { x25519PrivateFromRaw, type Keystore } from './keystore.js'

export interface SkillSummary {
  name: string
  description: string
  whenToUse?: string
  invocation: { modelInvocable: boolean; userInvocable: boolean }
}
export interface SkillDefinition extends SkillSummary { content: string }

export type SealedErrorCode = 'PACK_SIGNATURE' | 'LICENSE_INVALID' | 'LICENSE_EXPIRED' | 'NOT_GRANTED' | 'DECRYPT_FAILED' | 'META_INVALID'
export class SealedError extends Error {
  constructor(readonly code: SealedErrorCode, message: string) {
    super(message)
    this.name = 'SealedError'
  }
}

interface MetaShape {
  skills: (SkillSummary & { entries: string[] })[]
  resources: Record<string, string>
}

function isSkillMeta(value: unknown): value is SkillSummary & { entries: string[] } {
  if (value === null || typeof value !== 'object') return false
  const skill = value as Record<string, unknown>
  if (typeof skill.name !== 'string' || typeof skill.description !== 'string') return false
  const invocation = skill.invocation
  if (invocation === null || typeof invocation !== 'object') return false
  const inv = invocation as Record<string, unknown>
  if (typeof inv.modelInvocable !== 'boolean' || typeof inv.userInvocable !== 'boolean') return false
  if (!Array.isArray(skill.entries) || !skill.entries.every((entry) => typeof entry === 'string')) return false
  if (skill.whenToUse !== undefined && typeof skill.whenToUse !== 'string') return false
  return true
}

export class SealedCore {
  private readonly parsed: ReturnType<typeof readContainer>
  private readonly payload: LicensePayload
  private meta?: MetaShape

  constructor(private readonly opts: {
    pack: Buffer
    authorPublicKeyB64: string
    license: string
    trustedLicenseKeys: KeyObject[]
    keystore: Keystore
    now?: () => number
  }) {
    this.parsed = readContainer(opts.pack)
    const authorKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: opts.authorPublicKeyB64 }, format: 'jwk' })
    if (!verifyManifestSignature(this.parsed.manifestBytes, this.parsed.signature, authorKey)) {
      throw new SealedError('PACK_SIGNATURE', 'pack manifest signature does not match the trusted author key')
    }
    this.payload = verifyLicense(opts.license, opts.trustedLicenseKeys)
    if (this.payload.pack.id !== this.parsed.manifest.pack_id || this.payload.pack.version !== this.parsed.manifest.version) {
      throw new SealedError('LICENSE_INVALID', 'license is for a different pack or version')
    }
  }

  async list(): Promise<SkillSummary[]> {
    const meta = await this.loadMeta()
    return meta.skills.map((skill) => {
      const summary: SkillSummary = { name: skill.name, description: skill.description, invocation: skill.invocation }
      if (skill.whenToUse) summary.whenToUse = skill.whenToUse
      return summary
    })
  }

  async readSkill(name: string): Promise<SkillDefinition> {
    const meta = await this.loadMeta()
    const skill = meta.skills.find((s) => s.name === name)
    if (!skill) throw new SealedError('META_INVALID', 'no such skill: ' + name)
    const bodyId = 'skill:' + name + ':body'
    if (!skill.entries.includes(bodyId)) throw new SealedError('META_INVALID', 'skill has no body entry')
    const content = (await this.readEntry(bodyId)).toString('utf8')
    const definition: SkillDefinition = { name: skill.name, description: skill.description, invocation: skill.invocation, content }
    if (skill.whenToUse) definition.whenToUse = skill.whenToUse
    return definition
  }

  async readEntry(id: string): Promise<Buffer> {
    this.assertUsable()
    const chunk = this.parsed.chunks.find((c) => c.id === id)
    if (!chunk) throw new SealedError('NOT_GRANTED', 'no such entry or not granted: ' + id)
    let raw: Buffer | undefined
    try {
      raw = await this.opts.keystore.loadDevicePrivateKey()
    } catch {
      throw new SealedError('LICENSE_INVALID', 'device keystore is unavailable')
    }
    if (!raw) throw new SealedError('LICENSE_INVALID', 'no device key is available')
    let deviceKey: KeyObject
    try {
      deviceKey = x25519PrivateFromRaw(raw)
    } finally {
      raw.fill(0)
    }
    // A missing grant (LICENSE_NO_GRANT) is a denial; any other unwrap fault is an authentication failure.
    const ck = this.unwrapGrantedKey(id, deviceKey)
    try {
      return openEntry(ck, entryAad(this.parsed.manifest.pack_id, this.parsed.manifest.version, id), chunk.nonce, chunk.ct)
    } catch {
      throw new SealedError('DECRYPT_FAILED', 'entry failed authentication: ' + id)
    } finally {
      ck.fill(0)
    }
  }

  private unwrapGrantedKey(id: string, deviceKey: KeyObject): Buffer {
    try {
      return unwrapEntryKey(this.payload, id, deviceKey)
    } catch (err) {
      if (err instanceof LicenseError && err.code === 'LICENSE_NO_GRANT') {
        throw new SealedError('NOT_GRANTED', 'license grants no key for entry: ' + id)
      }
      throw new SealedError('DECRYPT_FAILED', 'could not unwrap the entry key for: ' + id)
    }
  }

  private async loadMeta(): Promise<MetaShape> {
    if (!this.meta) {
      const raw = (await this.readEntry('meta')).toString('utf8')
      let parsed: unknown
      try {
        parsed = JSON.parse(raw)
      } catch {
        throw new SealedError('META_INVALID', 'meta entry is not valid JSON')
      }
      if (parsed === null || typeof parsed !== 'object') {
        throw new SealedError('META_INVALID', 'meta entry has an unexpected shape')
      }
      const meta = parsed as { skills?: unknown }
      if (!Array.isArray(meta.skills)) throw new SealedError('META_INVALID', 'meta entry has no skills array')
      for (const skill of meta.skills) {
        if (!isSkillMeta(skill)) throw new SealedError('META_INVALID', 'meta entry has a malformed skill')
      }
      this.meta = parsed as MetaShape
    }
    return this.meta
  }

  private assertUsable(): void {
    const nowMs = this.opts.now ? this.opts.now() : Date.now()
    if (licenseStatus(this.payload, nowMs) === 'expired') {
      throw new SealedError('LICENSE_EXPIRED', 'license expired past its grace period')
    }
  }
}
